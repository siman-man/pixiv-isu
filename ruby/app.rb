require 'fileutils'
require 'sinatra/base'
require 'rack-flash'
require 'shellwords'
require 'tilt/erubis'
require 'rack-mini-profiler'
require 'rack-lineprof'
require 'openssl'
require_relative 'db'

module Isuconp
  class App < Sinatra::Base
    use Rack::Session::Memcache, autofix_keys: true, secret: ENV['ISUCONP_SESSION_SECRET'] || 'sendagaya'
    use Rack::Flash
    use Rack::Lineprof if ENV['DEBUG']
    use Rack::MiniProfiler if ENV['DEBUG']
    set :public_folder, File.expand_path('../../public', __FILE__)

    UPLOAD_LIMIT = 10 * 1024 * 1024 # 10mb

    POSTS_PER_PAGE = 20

    helpers do
      def db_initialize
        sql = []
        sql << 'DELETE FROM users WHERE id > 1000'
        sql << 'DELETE FROM posts WHERE id > 10000'
        sql << 'DELETE FROM comments WHERE id > 100000'
        sql << 'UPDATE users SET del_flg = 0'
        sql << 'UPDATE users SET del_flg = 1 WHERE id % 50 = 0'
        sql.each do |s|
          db.prepare(s).execute
        end

        redis.flushall
      end

      def image_initialize
        Dir.glob(File.expand_path('../public/image/*.*', __dir__)).each do |path|
          id = File.basename(path).split('.').first.to_i

          if id > 10000
            FileUtils.remove_file(path)
          end
        end
      end

      def data_initialize
        db.prepare('select post_id, count(*) as comment_count from comments group by post_id;').execute.each do |result|
          key = post_comment_counter_key(result[:post_id])
          redis.set(key, result[:comment_count])
        end

        db.prepare('select user_id, count(*) as comment_count from comments group by user_id').execute.each do |result|
          key = user_comment_counter_key(result[:user_id])
          redis.set(key, result[:comment_count])
        end

        db.prepare('select id, user_id from posts').execute.each do |post|
          key = user_post_ids_key(post[:user_id])
          redis.rpush(key, post[:id])
        end

        @@user_list = {}
        db.prepare('select * from users').execute.each do |user|
          @@user_list[user[:id]] = user
        end
      end

      def user_list
        @@user_list
      end

      def post_comment_counter_key(id)
        "post#{id}:comment:count"
      end

      def user_comment_counter_key(id)
        "user#{id}:comment:count"
      end

      def user_post_ids_key(id)
        "users#{id}:posts:ids"
      end

      def try_login(account_name, password)
        user = user_list.find { |_id, u| p u; u[:del_flg] == 0 && u[:account_name] == account_name }

        if user && calculate_passhash(user[:account_name], password) == user[:passhash]
          return user
        elsif user
          return nil
        else
          return nil
        end
      end

      def validate_user(account_name, password)
        if !(/\A[0-9a-zA-Z_]{3,}\z/.match(account_name) && /\A[0-9a-zA-Z_]{6,}\z/.match(password))
          return false
        end

        return true
      end

      def digest(src)
        # opensslのバージョンによっては (stdin)= というのがつくので取る
        OpenSSL::Digest::SHA512.hexdigest(src)
      end

      def calculate_salt(account_name)
        digest account_name
      end

      def calculate_passhash(account_name, password)
        digest "#{password}:#{calculate_salt(account_name)}"
      end

      def get_session_user()
        if session[:user]
          user_list[session[:user][:id]]
        else
          nil
        end
      end

      def make_posts(results, all_comments: false)
        posts = []
        post_ids = results.map { |post| post[:id] }
        comment_store = db.prepare("SELECT post_id, user_id, comment FROM comments WHERE post_id in (#{post_ids.join(',')})").execute.to_a
        comment_counts = redis.mget(*post_ids.map {|pid| post_comment_counter_key(pid)}).map(&:to_i)

        results.to_a.each do |post|
          post[:comment_count] = comment_counts.shift

          if all_comments
            comments = comment_store.select { |comment| comment[:post_id] == post[:id] }
          else
            comments = comment_store.select { |comment| comment[:post_id] == post[:id] }.take(3)
          end

          comments.each do |comment|
            comment[:user] = user_list[comment[:user_id]]
          end
          post[:comments] = comments.reverse
          post[:user] = user_list[post[:user_id]]
          post[:user][:escaped_account_name] = escape_html(CGI.escape(post[:user][:account_name]))

          posts.push(post)
        end

        posts
      end

      def image_url(id, mime)
        ext = ""
        if mime == "image/jpeg"
          ext = ".jpg"
        elsif mime == "image/png"
          ext = ".png"
        elsif mime == "image/gif"
          ext = ".gif"
        end

        "/image/#{id}#{ext}"
      end
    end

    get '/initialize' do
      db_initialize
      image_initialize

      data_initialize
      return 200
    end

    get '/login' do
      if get_session_user()
        redirect '/', 302
      end
      erb :login, layout: :layout, locals: { me: nil }
    end

    post '/login' do
      if get_session_user()
        redirect '/', 302
      end

      user = try_login(params['account_name'], params['password'])
      if user
        session[:user] = {
          id: user[:id]
        }
        session[:csrf_token] = SecureRandom.hex(16)
        redirect '/', 302
      else
        flash[:notice] = 'アカウント名かパスワードが間違っています'
        redirect '/login', 302
      end
    end

    get '/register' do
      if get_session_user()
        redirect '/', 302
      end
      erb :register, layout: :layout, locals: { me: nil }
    end

    post '/register' do
      if get_session_user()
        redirect '/', 302
      end

      account_name = params['account_name']
      password = params['password']

      validated = validate_user(account_name, password)
      if !validated
        flash[:notice] = 'アカウント名は3文字以上、パスワードは6文字以上である必要があります'
        redirect '/register', 302
        return
      end

      user = db.prepare('SELECT 1 FROM users WHERE `account_name` = ?').execute(account_name).first
      if user
        flash[:notice] = 'アカウント名がすでに使われています'
        redirect '/register', 302
        return
      end

      query = 'INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)'
      db.prepare(query).execute(
        account_name,
        calculate_passhash(account_name, password)
      )

      session[:user] = {
        id: db.last_id
      }
      user = db.prepare('SELECT * FROM users WHERE `account_name` = ?').execute(account_name).first
      @@user_list[session[:user][:id]] = user
      session[:csrf_token] = SecureRandom.hex(16)
      redirect '/', 302
    end

    get '/logout' do
      session.delete(:user)
      redirect '/', 302
    end

    get '/' do
      me = get_session_user()

      results = db.query('SELECT `posts`.`id`, `user_id`, `body`, `posts`.`created_at`, `mime` FROM `posts` INNER JOIN users on `posts`.`user_id` = `users`.id where del_flg = 0 ORDER BY `posts`.`created_at` DESC LIMIT 20')
      posts = make_posts(results)

      erb :index, layout: :layout, locals: { posts: posts, me: me }
    end

    get '/@:account_name' do
      user = db.prepare('SELECT id, account_name FROM `users` WHERE `account_name` = ? AND `del_flg` = 0').execute(
        params[:account_name]
      ).first

      if user.nil?
        return 404
      end

      results = db.prepare('SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC LIMIT 20').execute(
        user[:id]
      )
      posts = make_posts(results)

      key = user_comment_counter_key(user[:id])
      comment_count = redis.get(key).to_i

      key = user_post_ids_key(user[:id])
      post_ids = redis.lrange(key, 0, -1)
      post_count = post_ids.length

      commented_count = 0
      if post_count > 0
        commented_count = redis.mget(*post_ids.map {|pid| post_comment_counter_key(pid)}).map(&:to_i).inject(:+)
      end

      me = get_session_user()

      erb :user, layout: :layout, locals: { posts: posts, user: user, post_count: post_count, comment_count: comment_count, commented_count: commented_count, me: me }
    end

    get '/posts' do
      max_created_at = params['max_created_at']
      results = db.prepare('SELECT `posts`.`id`, `user_id`, `body`, `mime`, `posts`.`created_at` FROM `posts` INNER JOIN users ON `posts`.`user_id` = `users`.id WHERE `posts`.`created_at` <= ? AND del_flg = 0 ORDER BY `created_at` DESC LIMIT 20').execute(
        max_created_at.nil? ? nil : Time.iso8601(max_created_at).localtime
      )
      posts = make_posts(results)

      erb :posts, layout: false, locals: { posts: posts }
    end

    get '/posts/:id' do
      results = db.prepare('SELECT * FROM `posts` WHERE `id` = ? LIMIT 20').execute(
        params[:id]
      )
      posts = make_posts(results, all_comments: true)

      return 404 if posts.length == 0

      post = posts[0]

      me = get_session_user()

      erb :post, layout: :layout, locals: { post: post, me: me }
    end

    post '/' do
      me = get_session_user()

      if me.nil?
        redirect '/login', 302
      end

      if params['csrf_token'] != session[:csrf_token]
        return 422
      end

      if params['file']
        mime = ''
        # 投稿のContent-Typeからファイルのタイプを決定する
        if params["file"][:type].include? "jpeg"
          mime = "image/jpeg"
        elsif params["file"][:type].include? "png"
          mime = "image/png"
        elsif params["file"][:type].include? "gif"
          mime = "image/gif"
        else
          flash[:notice] = '投稿できる画像形式はjpgとpngとgifだけです'
          redirect '/', 302
        end

        if params['file'][:tempfile].read.length > UPLOAD_LIMIT
          flash[:notice] = 'ファイルサイズが大きすぎます'
          redirect '/', 302
        end

        params['file'][:tempfile].rewind
        query = 'INSERT INTO `posts` (`user_id`, `mime`, `body`) VALUES (?,?,?)'
        db.query("LOCK TABLES posts WRITE")
        db.prepare(query).execute(
          me[:id],
          mime,
          params["body"],
        )
        pid = db.last_id
        db.query("UNLOCK TABLES")

        img_path = File.expand_path("../public" + image_url(pid, mime))
        File.write(img_path, params["file"][:tempfile].read)

        redirect "/posts/#{pid}", 302
      else
        flash[:notice] = '画像が必須です'
        redirect '/', 302
      end
    end

    post '/comment' do
      me = get_session_user()

      if me.nil?
        redirect '/login', 302
      end

      if params["csrf_token"] != session[:csrf_token]
        return 422
      end

      unless /\A[0-9]+\z/.match(params['post_id'])
        return 'post_idは整数のみです'
      end
      post_id = params['post_id']

      query = 'INSERT INTO `comments` (`post_id`, `user_id`, `comment`, `escaped_comment`) VALUES (?,?,?,?)'
      db.prepare(query).execute(
        post_id,
        me[:id],
        params['comment'],
        CGI.escape_html(params['comment'])
      )

      key = post_comment_counter_key(post_id)
      redis.incr(key)

      key = user_comment_counter_key(me[:id])
      redis.incr(key)

      redirect "/posts/#{post_id}", 302
    end

    get '/admin/banned' do
      me = get_session_user()

      if me.nil?
        redirect '/login', 302
      end

      if me[:authority] == 0
        return 403
      end

      users = db.query('SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC')

      erb :banned, layout: :layout, locals: { users: users, me: me }
    end

    post '/admin/banned' do
      me = get_session_user()

      if me.nil?
        redirect '/', 302
      end

      if me[:authority] == 0
        return 403
      end

      if params['csrf_token'] != session[:csrf_token]
        return 422
      end

      query = 'UPDATE `users` SET `del_flg` = ? WHERE `id` = ?'

      params['uid'].each do |id|
        db.prepare(query).execute(1, id.to_i)
      end

      redirect '/admin/banned', 302
    end
  end
end
