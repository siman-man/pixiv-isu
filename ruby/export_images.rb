require_relative 'db'

public_path = File.expand_path('../public/image', __dir__)

db.prepare('SELECT * FROM posts').execute.each do |post|
  _, ext = post[:mime].split('/')
  image_name = "#{post[:id]}.#{ext}"
  File.write(File.join(public_path, image_name), post[:imgdata])
end
