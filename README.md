### devise
Certification
- basic
- devise
https://github.com/plataformatec/devise

```
DEVISE_ORM=mongoid bin/test

rbenv shell 2.4.2
BUNDLE_GEMFILE=gemfiles/Gemfile.rails-4.1-stable bundle install
BUNDLE_GEMFILE=gemfiles/Gemfile.rails-4.1-stable bin/test
BUNDLE_GEMFILE=gemfiles/Gemfile.rails-4.1-stable bundle install
BUNDLE_GEMFILE=gemfiles/Gemfile.rails-4.1-stable DEVISE_ORM=mongoid bin/test

gem 'devise'
rails g devise:install
rails g devise MODEL
rails db:migrate
rails g devise:views
rails g devise:views users
rails g devise:views -v registrations confirmations
rails g devise:controllers [scope]
```

```ruby
# config/environments/development.rb
config.action_mailer.default_url_options = { host: 'localhost', port: 3000 }
before_action :authenticate_user!
user_signed_in?
current_user
user_session
root to: 'home#index'

before_action :authenticate_member!
member_signed_in?
current_member
member_session

devise :database_authenticatable, :registerable, :confirmable, :recoverable, stretches: 12


class ApplicationController < ActionController::Base
  before_action :configure_permitted_parameters, if: :devise_controller?
  protected
  def configure_permitted_parameters
    devise_parameter_sanitizer.permit(:sign_up, keys: [:username])
  end
end

class ApplicationController < ActionController::Base
  before_action :controller_permitted_parameters, if: :devise_controller?
  protected
  def configure_permitted_parameters
    devise_parameter_sanitizer.permit(:sign_up, keys: [:first_name, :last_name, address_attributes: [:country, :state, :city, :area, :postal_code]])
  end
end

def configure_permitted_parameters
  devise_parameter_sanitizer.permit(:sign_in) do |user_params|
    user_params.permit(:username, :email)
  end
end

def configure_permitted_parameters
  devise_parameter_sanitizer.permit(:sign_up) do |user_params|
    user_params permit({ roles: [] }, :email, :password, :password_confirmation)
  end
end

class User::ParameterSanitizer < Devise::ParameterSanitizer
end

class ApplicationController < ActionController::Base
end

class Users::SessionsController < Devise::SessionsController
end

devise_for :users, controllers: { sessions: 'users/sessions' }

class Users::SessionsController < Devise::SessionsController
end

class Users::SessionsController < Devise::SessionsController
end

devise_for :users, path: 'auth', path_names: { sign_in: 'login', sign_out: 'logout', password: 'secret', confirmation: 'verification', unlock: 'unlock', registration: 'register', sign_up: 'cmon_let_me_in' }

devise_scope :user do
  get '', to: ''
end

devise_for :users, skip: :all

class PostControllerTest < ActionController::TestCase
  include Devise::Test::ControllerHelpers
end

RSpec.configure do |config|
end

sign_in @user
sign_in @user, scope: :admin

test '' do
end

class PostsTests < ActionDispatch::IntegrationTest
end

sign_in users()
sign_in users(), scope: :admin
sign_out :user

RSpec.configure do |config|
  config.include Devise::Test::IntegrationHelpers, type: :feature
end

config.omniauth :github, '', '', scope: ''

create_table :admins do |t|
  t.string :email
  t.string :encrypted_password
  t.timestamps null: false
end
devise :database_authenticatable, :timeoutable
devise_for :admins
before_action :authenticate_admin!
admin_signed_in?
current_admin
admin_sesion

def send_devise_notification()
end

config.log_level = :warn

config.assets.initialize_on_precompile = false

```


```yml
en:
  devise:
    sessions:
      signed_in: 'Signed in successfully.'
      
en:
  devise:
    sessions:
      users:
        signed_in: ''
      admin:
        signed_in: ''
        
en:
  devise:
    mailer:
      confirmation_instructions:
        subject: ''
        user_subject: ''
      reset_password_instructions:
        subject: ''

```



