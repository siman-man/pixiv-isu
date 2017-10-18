require 'active_record'
require 'pry'
require_relative './db'

ActiveRecord::Base.establish_connection config[:db].merge(adapter: :mysql2)
ActiveRecord::Base.logger = Logger.new(STDOUT)

class User < ActiveRecord::Base
  has_many :posts
  has_many :comments
end

class Post < ActiveRecord::Base
  belongs_to :user
  has_many :comments
end

class Comment < ActiveRecord::Base
  belongs_to :user
  belongs_to :post
end

binding.pry
