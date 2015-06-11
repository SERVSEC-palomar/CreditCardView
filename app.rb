### MAIN
require "sinatra"
require "json"
require "config_env"
require 'rack-flash'
require_relative './model/user.rb'
require_relative './helpers/creditcard_helpers.rb'
require 'rack/ssl-enforcer'
require 'httparty'

# Credit Card Web Service
class CreditCardAPI < Sinatra::Base
  include CreditCardHelper

  API_URL_BASE = 'https://palomar-creditcardapi.herokuapp.com/'

  enable :logging

  configure :production do
    use Rack::SslEnforcer
    set :session_secret, ENV['MSG_KEY']
  end

  configure do
    use Rack::Session::Cookie, secret: settings.session_secret
    use Rack::Flash, sweep: true
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

  register do
    def auth(*types)
      condition do
        if (types.include? :user) && !@current_user
          flash[:error] = 'You must be logged in to view that page'
          redirect '/login'
        end
      end
    end
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

  get '/user/:username', :auth => [:user] do
    username = params[:username]
    unless username == @current_user.username
      flash[:error] = 'You may only look at your own profile'
      redirect '/'
    end
    
    haml :profile
  end

  configure :development, :test do
    require 'hirb'
    Hirb.enable
    ConfigEnv.path_to_config("#{__dir__}/config/config_env.rb")
  end

  get '/' do
    haml :index # "The CreditCardAPI service is running"
  end

  get '/api/v1/credit_card/?' do
    logger.info('FEATURES')
    'TO date, services offered include<br>' \
    ' GET api/v1/credit_card/validate?card_number=[card number]<br>' \
    #' GET <a href="/api/v1/credit_card/everything"> Numbers </a> '
  end

  get '/validate', :auth => [:user] do
    num = params['card_number']
    url = "#{API_URL_BASE}/api/v1/credit_card/validate/#{card_number}"
    @card = HTTParty.get (url)
    @valid = JSON.parse(@card)
    haml :validate
    #card = CreditCard.new(number: params[:card_number])
    #{"Card" => params[:card_number], "validated" => card.validate_checksum}.to_json
  end


#####   ADDing Card

  get '/add', :auth => [:user] do
    haml :add_creditcard
  end

  post '/add_creditcard', auth: [:user] do
    #card_json = JSON.parse(request.body.read)
    begin
      body = {
        'user_id' => @current_user.id,
        'number'  => params[:number],
        'expiration_date' => params[:expiration_date],
        'owner' => params[:owner],
        'credit_network'  => params[:credit_network]
      }.to_json
      response = HTTParty.post("#{API_URL_BASE}/api/v1/credit_card", {
        :body => data,
        :headers => {'Content-Type' => 'application/json', 'Accept' => 'application/json', 'authorization' => ('Bearer ' + user_jwt) }
        })
      if save.code == 201
        flash[:notice] = 'Added Successfully!'
      else
        flash[:error] = 'Incorrect Card Number'
      end
      redirect '/'
    rescue => e
      logger.error(e)
      halt 410
    end
  end

  get '/api/v1/credit_card/everything' do
    result = HTTParty.get("#{API_URL_BASE}/api/v1/credit_card/everything/#{@current_user.id}")
    @cc = result.parsed_response
    haml :everything#, locals: {result: CreditCard.all.map(&:to_s)    }
  end

end
