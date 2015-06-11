### MAIN
require "sinatra"
require "json"
require "config_env"
require 'rack-flash'
require_relative './model/user.rb'
require_relative './helpers/creditcard_helpers.rb'
require 'rack/ssl-enforcer'

configure :development, :test do
  ConfigEnv.path_to_config("#{__dir__}/config/config_env.rb")
end

# Credit Card Web Service
class CreditCardAPI < Sinatra::Base
  include CreditCardHelper
  require 'hirb'
  Hirb.enable

  enable :logging

  configure :production do
    use Rack::SslEnforcer
    set :session_secret, ENV['MSG_KEY']
  end

  configure do
    use Rack::Session::Cookie, secret: settings.session_secret
    use Rack::Flash, sweep: true
  end

  register do
    def auth(*types)
      condition do
        if (types.include? :user) && !@current_user
          flash[:error] = 'You must be logged in for that page'
          redirect '/login'
        end
      end
    end
  end

  before do
    @current_user = session[:auth_token] ? find_user_by_token(session[:auth_token]) : nil
  end

  get '/login' do
    haml :login
  end

  post '/login' do
    username = params[:username]
    password = params[:password]
    user = User.authenticate!(username, password)
    if user # user found
      login_user(user)
    else
      flash[:error] = 'User does not exists. <a href="/register"> Register here</a>'
      redirect '/login'
    end

  end

  get '/logout' do
    session[:auth_token] = nil
    redirect '/'
    flash[:notice] = 'You have been succesfully logged out.'
  end

  get '/register' do
    haml :register
    if token = params[:token]
      begin
        create_user_with_encrypted_token(token)
        flash[:notice] = 'Welcome! Your account has been successfully created.'
      rescue
        flash[:error] = 'Your account could not be created. Your link is either expired or is invalid'
      end
      redirect '/'
    else
      haml :register
    end
  end

  post '/register' do
    registration = Registration.new(params)

    if (registration.complete?) && (params[:password] == params[:password_confirm])
      begin
        email_registration_verification(registration)
        flash[:notice] = 'A verification link sent. Please check the email address provided.'
        redirect '/'
      rescue => e
        logger.error "FAIL EMAIL: #{e}"
        flash[:error] = 'Could not send registration verification: check email address'
        redirect '/register'
      end
    else
      flash[:error] = 'Please fill in all fields and make sure passwords match'
      redirect '/register'
    end
  end

  get '/' do
    haml :index # "The CreditCardAPI service is running"
  end

  get '/user/:username', :auth => [:user] do
    username = params[:username]
    unless username == @current_user.username
      flash[:error] = "You may only look at your own profile"
      redirect '/'
    end

    haml :profile
  end

  get '/credit_card/?', :auth => [:user] do
    haml :register_cards
    # 'TO date, services offered include<br>' \
    # ' GET api/v1/credit_card/validate?card_number=[card number]<br>' \
    # ' GET <a href="/api/v1/credit_card/everything"> Numbers </a> '
  end

  get '/credit_card/validate', :auth => [:user] do
    if params[:number]
      begin
        number = params[:number]
        save = api_validate(number)
        haml :validate, locals: { result: save.body }
      rescue => e
        logger.error(e)
        halt 410
      end
    else
      haml :validate, locals: { result: '' }
    end
  end

  post '/credit_card', :auth => [:user] do
    begin
      number = params[:number]
      credit_network = params[:credit_network]
      expiration_date = params[:expiration_date]
      owner = params[:owner]
      register = api_register(owner, expiration_date, credit_network, number)
      if register.code == 201
        flash[:notice] = 'Card registerd'
      else
        flash[:error] = 'Check card number'
      end
      redirect '/'
    rescue => e
      logger.error(e)
      halt 410
    end
  end

  get '/credit_card/everything' do
    cards = api_everything
    cards = cards.body.gsub('}{', '}}{{').split('}{')
    cards = cards.map { |e| JSON.parse(e).to_a }
    cards = cards.map do |variable|
      variable.map { |_, f| f }
    end
    haml :everything, locals: {result: cards }
  end

end
