# Created user login
require 'rbnacl/libsodium'
require 'jwt'
require 'openssl'
require 'httparty'
require 'base64'
# require 'pony' # not using pony here

# Some documentation
module CreditCardHelper
  API_URL = 'https://palomar-api.herokuapp.com/api/v1/'
  # API_URL = 'http://127.0.0.1:9393/api/v1/'

  # Some documentation
  class Registration
    attr_accessor :username, :password, :email, :dob, :address, :fullname

    def initialize(user_data)
      @username = user_data[:username] || user_data['username']
      @password = user_data[:password] || user_data['password']
      @email = user_data[:email] || user_data['email']
      @dob = user_data[:dob] || user_data['dob']
      @address = user_data[:address] || user_data['address']
      @fullname = user_data[:fullname] || user_data['fullname']
    end

    def complete?
      (username && username.length > 0) &&
        (email && email.length > 0) &&
        (password && password.length > 0) &&
        (dob && dob.length > 0) &&
        (address && address.length > 0) &&
        (fullname && fullname.length > 0)
    end
  end

  def user_jwt
    jwt_payload = {
      'iss' => 'https://palomar-api.herokuapp.com/',
      'sub' => @current_user.id
    }
    jwt_key = OpenSSL::PKey::RSA.new(ENV['UI_PRIVATE_KEY'])
    JWT.encode jwt_payload, jwt_key, 'RS256'
  end

  def api_register(owner, expiration_date, credit_network, number)
    url = API_URL + 'credit_card'
    body_json = { owner: owner, expiration_date: expiration_date,
                  credit_network: credit_network, number: number }.to_json
    headers = { 'authorization' => ('Bearer ' + user_jwt) }
    HTTParty.post url, body: body_json, headers: headers
  end

  def api_everything
    url = API_URL + 'credit_card?user_id=RQST'
    headers = { 'authorization' => ('Bearer ' + user_jwt) }
    result = HTTParty.get url, headers: headers
    result.body
  end

  def api_validate(number)
    url = API_URL + "credit_card/validate?number=#{number}"
    headers = { 'authorization' => ('Bearer ' + user_jwt) }
    HTTParty.get url, headers: headers
  end

  def email_registration_verification(registration)
    payload = { username: registration.username, email: registration.email,
                password: registration.password, dob: registration.dob,
                address: registration.address, fullname: registration.fullname }
    token = JWT.encode payload, ENV['MSG_KEY'], 'HS256'
    verification = encrypt_message(token)
    Pony.mail(to: registration.email,
              subject: 'Your CreditCardAPI Account is Ready.',
              html_body: registration_email(verification))
  end

  def registration_email(token)
    verification_url = "#{request.base_url}/register?token=#{token}"
    '<H1>CreditCardAPI Registration Received</H1>'\
    "<p>Please <a href=\"#{verification_url}\">click here</a> to validate "\
    'your email and activate your account.</p>'
  end

  def encrypt_message(message)
    key = Base64.urlsafe_decode64(ENV['MSG_KEY'])
    secret_box = RbNaCl::SecretBox.new(key)
    nonce = RbNaCl::Random.random_bytes(secret_box.nonce_bytes)
    nonce_s = Base64.urlsafe_encode64(nonce)
    message_enc = secret_box.encrypt(nonce, message.to_s)
    message_enc_s = Base64.urlsafe_encode64(message_enc)
    Base64.urlsafe_encode64({ 'message' => message_enc_s,
                              'nonce' => nonce_s }.to_json)
  end

  def decrypt_message(secret_message)
    key = Base64.urlsafe_decode64(ENV['MSG_KEY'])
    secret_box = RbNaCl::SecretBox.new(key)
    message_h = JSON.parse(Base64.urlsafe_decode64(secret_message))
    message_enc = Base64.urlsafe_decode64(message_h['message'])
    nonce = Base64.urlsafe_decode64(message_h['nonce'])
    secret_box.decrypt(nonce, message_enc)
  rescue
    raise 'INVALID ENCRYPTED MESSAGE'
  end

  def create_account_with_registration(registration)
    new_user = User.new(username: registration.username,
                        email: registration.email)
    new_user.password = registration.password
    new_user.dob = registration.dob
    new_user.address = registration.address
    new_user.fullname = registration.fullname
    new_user.save ? login_user(new_user) : fail('Could not create new user')
  end

  def create_git_registration(login, email)
    new_user = User.new(username: login, email: email)
    new_user.password = Base64.urlsafe_encode64(RbNaCl::Random.random_bytes(20))
    new_user.save ? login_user(new_user) : fail('Could not create new user')
  end

  def git_get_info(links, access_token)
    a = b = {}
    links.each_with_index do |link, idx|
      info = HTTParty.get(
        "https://api.github.com/user#{link}",
        headers: { 'User-Agent' => 'stonegold546',
                   'authorization' => ("token #{access_token}") }
      )
      idx == 0 ? a = info : b = info
    end
    [a, b]
  end

  def create_user_with_encrypted_token(token_enc)
    token = decrypt_message(token_enc)
    payload = (JWT.decode token, ENV['MSG_KEY']).first
    reg = Registration.new(payload)
    create_account_with_registration(reg)
  end

  def login_user(user)
    payload = { user_id: user.id }
    token = JWT.encode payload, ENV['MSG_KEY'], 'HS256'
    session[:auth_token] = token
    redirect '/'
  end

  def find_user_by_token(token)
    return nil unless token
    decoded_token = JWT.decode token, ENV['MSG_KEY'], true
    payload = decoded_token.first
    User.find_by_id(payload['user_id'])
  end

  def memcache
    cards = settings.ops_cache.fetch(@current_user.id)
    cards = api_everything if cards == '' || cards.nil?
    JSON.parse(cards).to_a
  end
end
