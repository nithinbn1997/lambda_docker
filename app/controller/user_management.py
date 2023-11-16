import boto3 
import hmac
import base64
import hashlib
import base64
import pprint
import psycopg2
from datetime import datetime, timedelta, timezone
import botocore.exceptions
#boto3.set_stream_logger('')

db_host = 'authdb-staging.cyjwzxjq2hah.us-east-1.rds.amazonaws.com'
db_name = 'authdb_staging'
db_user = 'authdb_staging_user'
db_password = 'BaQtoElZyi3SHnO'
port = '5432'

client = boto3.client('cognito-idp',region_name='us-east-1')
pp = pprint.PrettyPrinter(indent=4)

# Define the lockout period in seconds (15 minutes)
lockout_period = 15 * 60

# Define the UTC timezone
utc = timezone.utc


dev_user_pool_id = "us-east-1_iRRWhIuAS"
uat_user_pool_id = "us-east-1_3dObWpLQv"
preprod_user_pool_id = "us-east-1_msrY2BMWC"
mef_user_pool_id = "us-east-1_1S2G54MuD"

dev_client_id = "1rqiihqct9clk06mu409n515f4" #dev
dev_client_secret = "76bt9a08de7o9ne1agl1gdfd9dv8mb4ib8n9lsgc5g5opim1qtm"

uat_client_id = "4udesi7oqebaoub77qgb8f1ps7" #dev
uat_client_secret = "1all2qea465bud9507pk7v85badh07as0lej6aiiaglq3ste7c79"

preprod_client_id = "4ikdacc8fe9uv8ir52pugsn30n" #dev
preprod_client_secret = "18ljblstq9r2a4kjsd7riocm42nrgvdpvr8smcls6peba1vdkobl"

mef_client_id = "4i65gc9760qa1g8n7s43qqleau" #dev
mef_client_secret = "nt0j9704ub3gqbiddadt7tmfq72cimk1vd8sv1t8g3jvfc6l7s1"

dev_gl_public_keys = [{"alg":"RS256","e":"AQAB","kid":"vrDDtlVDIeuhANKUN1ZnFQp76kg3gV9Oqo9DxDS2Y0k=","kty":"RSA","n":"xizjOONSAXcVIUt-GymecK8-kcS6pSM9moSyOImWpLoytLfrbFceJNLBsUhcJeaPXhJkO6lGfVEC10-wEBUOiUOBqCulcdZOCGldGwN_gy5T1q3CAKFOsU-TF0D1ppIxhx-E3JHhrXQ3v-jrLUg2xN5slIuiHx_KsSlVpVs22HKIbPQQDzE_usmE2nkq-AIQX80lX9sJSk4pUDthDzBT9Oh2JS-mlBtaWwyfKpW06eGRDpScP-_4uKppPbQCErGPHk8Z8Z0rF_EWTnLDdx3ilTwHnH4646xjdo5KjhvKAxVo_bSFAnzwZQR5qHvz5emx0vig1uTmQPTbtVih-5sKJQ","use":"sig"}]
uat_gl_public_keys = [{"alg":"RS256","e":"AQAB","kid":"poG3omrL0haOABNMNF68Z7vaNUIMcw44FH98DtAbMgw=","kty":"RSA","n":"uFeRn7ddDcER7Y_KJJBYCrpSfeWLANZgdksFQaL7Hc4ZF_kPX9Yks_TWfZwvOPE77IbrBddLRZxnWYQm2xXMX9coruKhldqXswhZXF1-M7ALRSKOS9JFhlXyNSBjds28DqUDZNaM6AZ_B9rvLMumcnNF5b6RcMNI6NpXtZtzNuMATCnm5m6BSJ8KWaZXMJCbgJOJZc2kxwVdBK8ROTO9y_WoX_9usZcwWwt8RHKItzEcTqsuzLKb12_-cHR_l0QH85NjzgP_RxqqbulPpotKyms8wyYl9_jVH2C9TY5_HLNXL9FtLMOAskWlKlBCNrIH9RImW8IDFcqhqNRgyAOFQQ","use":"sig"}]
preprod_gl_public_keys = [{"alg":"RS256","e":"AQAB","kid":"m3a78zaRXwHDwm4cvloDD+JVRirmqczB5SE3oJtlBVs=","kty":"RSA","n":"6szjMJXFMiAU3Wqi4NAK7vcF_bDIbLQtqaDcMi20hFAS3K9X6pX9jgnTUszbQwl4hzr-bcV8C28ZLrR2SiU3S1zQwAS0iN1Tu7CJ0CfxbrdL3yLX0AFcMBUPsQ71qUXUMgeC1NFrZsa_TWE4LvV2gVHQJpaO3PSVh1lylUoQ-54o12VkR_7Ips_yvgyxW_nsUlXa0-lbtyv2QErpZ5sZYYAT1UTczYdciCZlZsNfVlb_Mjk4_CVQocH2cL-ybpTcrQs0mNhnTUdrZ3WWuCcuMOvzb4kXfP-7u2oGMMpAE8Q8rJm57uUf3gyAlkplZiLzfcRd1oShRbtOCbaDl5z2wQ","use":"sig"}]
mef_gl_public_keys = [{"alg":"RS256","e":"AQAB","kid":"44ISeY8sT36R9lPT4DdC6KeYYHFbKSvzvWdHMPBnB+U=","kty":"RSA","n":"x8G5q9mlWaxx4W_FZ_c0KbJGio_JNhu3asZwsQznGsy5Nuct42YYZpXvW4qDMXqS5Leqorp1O-dIP2bpNqFpo_cD9JiHDGA_cJaGiDu3emGECoM6Sk6PaXo5fkvV7W4nsi4HHSjhkHcJH8v0u3seiWKtf_YELGJibCta9zZ91Y4wdVKLvVKVhBcKXCC2vxOKOLML5fNMywvDdx205SHDSTfDxdWDM3OlLNgmhZ9ud_aiRdczFo1YTHaC5unN96J1Oz5lC8aOXGzSno0PGBTgH9l7OWawQFhK6jDvnDoEenSQMYDq3j5vDJcEJP2izoMJTGZyTE1JSRrvKtjJgty29w","use":"sig"}]

# qarbon_admin
qarbon_admin = "79ca154c-a031-7070-7e81-f7b05b0e12f5"


def dev_get_user_id(user_name_string):
    response = client.admin_get_user(
        UserPoolId=dev_user_pool_id,
        Username=user_name_string
    )
    print(response)
    # Assume first item is always sub
    user_id = response.get("UserAttributes")[0]["Value"]
    return user_id

def uat_get_user_id(user_name_string):
    response = client.admin_get_user(
        UserPoolId=uat_user_pool_id,
        Username=user_name_string
    )
    print(response)
    # Assume first item is always sub
    user_id = response.get("UserAttributes")[0]["Value"]
    return user_id

def preprod_get_user_id(user_name_string):
    response = client.admin_get_user(
        UserPoolId=preprod_user_pool_id,
        Username=user_name_string
    )
    print(response)
    # Assume first item is always sub
    user_id = response.get("UserAttributes")[0]["Value"]
    return user_id

def mef_get_user_id(user_name_string):
    response = client.admin_get_user(
        UserPoolId=mef_user_pool_id,
        Username=user_name_string
    )
    print(response)
    # Assume first item is always sub
    user_id = response.get("UserAttributes")[0]["Value"]
    return user_id

def dev_get_secret_hash(user_name):
    key = bytes(dev_client_secret, 'latin-1')
    msg = bytes(user_name + dev_client_id , 'latin-1')
    new_digest = hmac.new(key, msg, hashlib.sha256).digest()
    secret_hash = base64.b64encode(new_digest).decode()
    return secret_hash

def uat_get_secret_hash(user_name):
    key = bytes(uat_client_secret, 'latin-1')
    msg = bytes(user_name + uat_client_id , 'latin-1')
    new_digest = hmac.new(key, msg, hashlib.sha256).digest()
    secret_hash = base64.b64encode(new_digest).decode()
    return secret_hash
    
def preprod_get_secret_hash(user_name):
    key = bytes(preprod_client_secret, 'latin-1')
    msg = bytes(user_name + preprod_client_id , 'latin-1')
    new_digest = hmac.new(key, msg, hashlib.sha256).digest()
    secret_hash = base64.b64encode(new_digest).decode()
    return secret_hash
    
def mef_get_secret_hash(user_name):
    key = bytes(mef_client_secret, 'latin-1')
    msg = bytes(user_name + mef_client_id , 'latin-1')
    new_digest = hmac.new(key, msg, hashlib.sha256).digest()
    secret_hash = base64.b64encode(new_digest).decode()
    return secret_hash 
      

         

def trigger_pre_auth_dev(user_name, user_id):
    
    #response = None  # Initialize response with None
    
    # Connect to the PostgreSQL database
    conn = psycopg2.connect(
        host=db_host,
        database=db_name,
        user=db_user,
        password=db_password,
        port = port,
    )
    cursor = conn.cursor()
    
    
    
    # Get the current time in UTC
    current_time = datetime.now(utc)
    print('current_time', current_time)

    # Check if the user's record exists in the table
    cursor.execute("SELECT failed_login_attempts, lockout_timestamp FROM user_lockout WHERE user_id = %s", (user_id,))
    lockout_info = cursor.fetchone()

    if lockout_info:
        # User's record exists, increment failed_login_attempts
        failed_login_attempts, lockout_timestamp = lockout_info
        
        print('failed_login_attempts:', failed_login_attempts)
        
        
        if current_time > lockout_timestamp:
            # User's waiting period has passed, delete the record
            cursor.execute("UPDATE user_lockout SET failed_login_attempts = 0 WHERE user_id = %s", (user_id,))
            conn.commit()
            

        if failed_login_attempts >= 5 and current_time < lockout_timestamp:
            # The user is locked out
            time_remaining = lockout_timestamp - current_time
            print('time_remaining: ', time_remaining )
            formatted_time_remaining = str(time_remaining.total_seconds() // 60) + " minutes"
            print('formatted_time_remaining: ', formatted_time_remaining )
            
            response = client.admin_disable_user(
                UserPoolId = dev_user_pool_id,
                Username = user_name
            )
            # response = {
            #     "challengeName": "CUSTOM_CHALLENGE",
            #     "challengeMetadata": "Your account is temporarily locked for 15 minutes.",
            #     "failAuthentication": True
            # }
            
            
            cursor.close()
            conn.close()
            return response
            

        # Increment failed_login_attempts
        new_failed_attempts = failed_login_attempts + 1

        # Calculate the new lockout timestamp
        new_lockout_timestamp = current_time + timedelta(seconds=lockout_period)

        cursor.execute("UPDATE user_lockout SET failed_login_attempts = %s, lockout_timestamp = %s WHERE user_id = %s", (new_failed_attempts, new_lockout_timestamp, user_id))

    else:
        # User's record does not exist, create a new record
        # Set an initial lockout_timestamp in the past
        initial_lockout_timestamp = current_time + timedelta(seconds=lockout_period)
        cursor.execute("INSERT INTO user_lockout (user_id, failed_login_attempts, lockout_timestamp) VALUES (%s, 1, %s)", (user_id, initial_lockout_timestamp))

    conn.commit()
    cursor.close()
    conn.close()

def trigger_pre_auth_uat(user_name, user_id):
    response = None  # Initialize response with None
    
    # Connect to the PostgreSQL database
    conn = psycopg2.connect(
        host=db_host,
        database=db_name,
        user=db_user,
        password=db_password,
        port = port,
    )
    cursor = conn.cursor()
    
    
    
    # Get the current time in UTC
    current_time = datetime.now(utc)
    print('current_time', current_time)

    # Check if the user's record exists in the table
    cursor.execute("SELECT failed_login_attempts, lockout_timestamp FROM user_lockout WHERE user_id = %s", (user_id,))
    lockout_info = cursor.fetchone()

    if lockout_info:
        # User's record exists, increment failed_login_attempts
        failed_login_attempts, lockout_timestamp = lockout_info
        
        print('failed_login_attempts:', failed_login_attempts)
        
        
        if current_time > lockout_timestamp:
            # User's waiting period has passed, delete the record
            cursor.execute("UPDATE user_lockout SET failed_login_attempts = 0 WHERE user_id = %s", (user_id,))
            conn.commit()
            

        if failed_login_attempts >= 5 and current_time < lockout_timestamp:
            # The user is locked out
            time_remaining = lockout_timestamp - current_time
            print('time_remaining: ', time_remaining )
            formatted_time_remaining = str(time_remaining.total_seconds() // 60) + " minutes"
            print('formatted_time_remaining: ', formatted_time_remaining )
            
            response = client.admin_disable_user(
                UserPoolId = uat_user_pool_id,
                Username = user_name
            )
            # response = {
            #     "challengeName": "CUSTOM_CHALLENGE",
            #     "challengeMetadata": "Your account is temporarily locked for 15 minutes.",
            #     "failAuthentication": True
            # }
            cursor.close()
            conn.close()
            return response

        # Increment failed_login_attempts
        new_failed_attempts = failed_login_attempts + 1

        # Calculate the new lockout timestamp
        new_lockout_timestamp = current_time + timedelta(seconds=lockout_period)

        cursor.execute("UPDATE user_lockout SET failed_login_attempts = %s, lockout_timestamp = %s WHERE user_id = %s", (new_failed_attempts, new_lockout_timestamp, user_id))

    else:
        # User's record does not exist, create a new record
        # Set an initial lockout_timestamp in the past
        initial_lockout_timestamp = current_time + timedelta(seconds=lockout_period)
        cursor.execute("INSERT INTO user_lockout (user_id, failed_login_attempts, lockout_timestamp) VALUES (%s, 1, %s)", (user_id, initial_lockout_timestamp))

    conn.commit()
    cursor.close()
    conn.close()

    print('pre_auth_damin_disable_user response:', response)
    return response  # You can return any value or None as needed    
    
def trigger_pre_auth_mef(user_name, user_id):
    
    response = None  # Initialize response with None
    
    # Connect to the PostgreSQL database
    conn = psycopg2.connect(
        host=db_host,
        database=db_name,
        user=db_user,
        password=db_password,
        port = port,
    )
    cursor = conn.cursor()
    
    
    
    # Get the current time in UTC
    current_time = datetime.now(utc)
    print('current_time', current_time)

    # Check if the user's record exists in the table
    cursor.execute("SELECT failed_login_attempts, lockout_timestamp FROM user_lockout WHERE user_id = %s", (user_id,))
    lockout_info = cursor.fetchone()

    if lockout_info:
        # User's record exists, increment failed_login_attempts
        failed_login_attempts, lockout_timestamp = lockout_info
        
        print('failed_login_attempts:', failed_login_attempts)
        
        
        if current_time > lockout_timestamp:
            # User's waiting period has passed, delete the record
            cursor.execute("UPDATE user_lockout SET failed_login_attempts = 0 WHERE user_id = %s", (user_id,))
            conn.commit()
            

        if failed_login_attempts >= 5 and current_time < lockout_timestamp:
            # The user is locked out
            time_remaining = lockout_timestamp - current_time
            print('time_remaining: ', time_remaining )
            formatted_time_remaining = str(time_remaining.total_seconds() // 60) + " minutes"
            print('formatted_time_remaining: ', formatted_time_remaining )
            
            response = client.admin_disable_user(
                UserPoolId = mef_user_pool_id,
                Username = user_name
            )
            # response = {
            #     "challengeName": "CUSTOM_CHALLENGE",
            #     "challengeMetadata": "Your account is temporarily locked for 15 minutes.",
            #     "failAuthentication": True
            # }
            cursor.close()
            conn.close()
            return response

        # Increment failed_login_attempts
        new_failed_attempts = failed_login_attempts + 1

        # Calculate the new lockout timestamp
        new_lockout_timestamp = current_time + timedelta(seconds=lockout_period)

        cursor.execute("UPDATE user_lockout SET failed_login_attempts = %s, lockout_timestamp = %s WHERE user_id = %s", (new_failed_attempts, new_lockout_timestamp, user_id))

    else:
        # User's record does not exist, create a new record
        # Set an initial lockout_timestamp in the past
        initial_lockout_timestamp = current_time + timedelta(seconds=lockout_period)
        cursor.execute("INSERT INTO user_lockout (user_id, failed_login_attempts, lockout_timestamp) VALUES (%s, 1, %s)", (user_id, initial_lockout_timestamp))

    conn.commit()
    cursor.close()
    conn.close()

    print('pre_auth_damin_disable_user response:', response)
    return response  # You can return any value or None as needed   

def trigger_pre_auth_preprod(user_name, user_id):
    
    response = None  # Initialize response with None
    
    # Connect to the PostgreSQL database
    conn = psycopg2.connect(
        host=db_host,
        database=db_name,
        user=db_user,
        password=db_password,
        port = port,
    )
    cursor = conn.cursor()
    
    
    
    # Get the current time in UTC
    current_time = datetime.now(utc)
    print('current_time', current_time)

    # Check if the user's record exists in the table
    cursor.execute("SELECT failed_login_attempts, lockout_timestamp FROM user_lockout WHERE user_id = %s", (user_id,))
    lockout_info = cursor.fetchone()

    if lockout_info:
        # User's record exists, increment failed_login_attempts
        failed_login_attempts, lockout_timestamp = lockout_info
        
        print('failed_login_attempts:', failed_login_attempts)
        
        
        if current_time > lockout_timestamp:
            # User's waiting period has passed, delete the record
            cursor.execute("UPDATE user_lockout SET failed_login_attempts = 0 WHERE user_id = %s", (user_id,))
            conn.commit()
            

        if failed_login_attempts >= 5 and current_time < lockout_timestamp:
            # The user is locked out
            time_remaining = lockout_timestamp - current_time
            print('time_remaining: ', time_remaining )
            formatted_time_remaining = str(time_remaining.total_seconds() // 60) + " minutes"
            print('formatted_time_remaining: ', formatted_time_remaining )
            
            response = client.admin_disable_user(
                UserPoolId = preprod_user_pool_id,
                Username = user_name
            )
            # response = {
            #     "challengeName": "CUSTOM_CHALLENGE",
            #     "challengeMetadata": "Your account is temporarily locked for 15 minutes.",
            #     "failAuthentication": True
            # }
            cursor.close()
            conn.close()
            return response

        # Increment failed_login_attempts
        new_failed_attempts = failed_login_attempts + 1

        # Calculate the new lockout timestamp
        new_lockout_timestamp = current_time + timedelta(seconds=lockout_period)

        cursor.execute("UPDATE user_lockout SET failed_login_attempts = %s, lockout_timestamp = %s WHERE user_id = %s", (new_failed_attempts, new_lockout_timestamp, user_id))

    else:
        # User's record does not exist, create a new record
        # Set an initial lockout_timestamp in the past
        initial_lockout_timestamp = current_time + timedelta(seconds=lockout_period)
        cursor.execute("INSERT INTO user_lockout (user_id, failed_login_attempts, lockout_timestamp) VALUES (%s, 1, %s)", (user_id, initial_lockout_timestamp))

    conn.commit()
    cursor.close()
    conn.close()

    print('pre_auth_damin_disable_user response:', response)
    return response  # You can return any value or None as needed
    

    
def trigger_post_auth(user_name, user_id):
    # Connect to the PostgreSQL database
    conn = psycopg2.connect(
        host=db_host,
        database=db_name,
        user=db_user,
        password=db_password,
        port = port,
    )
    cursor = conn.cursor()
    
    # The user has successfully logged in, reset failed_login_attempts
    cursor.execute("UPDATE user_lockout SET failed_login_attempts = 0 WHERE user_id = %s", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()
    
def check_lockout_time_dev(user_name, user_id):
    # Connect to the PostgreSQL database
    conn = psycopg2.connect(
        host=db_host,
        database=db_name,
        user=db_user,
        password=db_password,
        port=port,
    )
    cursor = conn.cursor()

    # Get the current time in UTC
    current_time = datetime.now(utc)
    print('current_time', current_time)

    # Check if the user's record exists in the table
    cursor.execute("SELECT lockout_timestamp FROM user_lockout WHERE user_id = %s", (user_id,))
    lockout_info = cursor.fetchone()

    if lockout_info:
        # Extract the lockout timestamp
        lockout_timestamp = lockout_info[0]

        if current_time > lockout_timestamp:
            # Reset failed login attempts to 0 and enable the user in Cognito
            cursor.execute("UPDATE user_lockout SET failed_login_attempts = 0 WHERE user_id = %s", (user_id,))
            conn.commit()

            client.admin_enable_user(
                UserPoolId=dev_user_pool_id,
                Username=user_name
            )

    cursor.close()
    conn.close()

def check_lockout_time_uat(user_name, user_id):
    # Connect to the PostgreSQL database
    conn = psycopg2.connect(
        host=db_host,
        database=db_name,
        user=db_user,
        password=db_password,
        port=port,
    )
    cursor = conn.cursor()

    # Get the current time in UTC
    current_time = datetime.now(utc)
    print('current_time', current_time)

    # Check if the user's record exists in the table
    cursor.execute("SELECT lockout_timestamp FROM user_lockout WHERE user_id = %s", (user_id,))
    lockout_info = cursor.fetchone()

    if lockout_info:
        # Extract the lockout timestamp
        lockout_timestamp = lockout_info[0]

        if current_time > lockout_timestamp:
            # Reset failed login attempts to 0 and enable the user in Cognito
            cursor.execute("UPDATE user_lockout SET failed_login_attempts = 0 WHERE user_id = %s", (user_id,))
            conn.commit()

            client.admin_enable_user(
                UserPoolId=uat_user_pool_id,
                Username=user_name
            )

    cursor.close()
    conn.close()    
    
def check_lockout_time_mef(user_name, user_id):
    # Connect to the PostgreSQL database
    conn = psycopg2.connect(
        host=db_host,
        database=db_name,
        user=db_user,
        password=db_password,
        port=port,
    )
    cursor = conn.cursor()

    # Get the current time in UTC
    current_time = datetime.now(utc)
    print('current_time', current_time)

    # Check if the user's record exists in the table
    cursor.execute("SELECT lockout_timestamp FROM user_lockout WHERE user_id = %s", (user_id,))
    lockout_info = cursor.fetchone()

    if lockout_info:
        # Extract the lockout timestamp
        lockout_timestamp = lockout_info[0]

        if current_time > lockout_timestamp:
            # Reset failed login attempts to 0 and enable the user in Cognito
            cursor.execute("UPDATE user_lockout SET failed_login_attempts = 0 WHERE user_id = %s", (user_id,))
            conn.commit()

            client.admin_enable_user(
                UserPoolId=mef_user_pool_id,
                Username=user_name
            )

    cursor.close()
    conn.close()     
    
def check_lockout_time_preprod(user_name, user_id):
    # Connect to the PostgreSQL database
    conn = psycopg2.connect(
        host=db_host,
        database=db_name,
        user=db_user,
        password=db_password,
        port=port,
    )
    cursor = conn.cursor()

    # Get the current time in UTC
    current_time = datetime.now(utc)
    print('current_time', current_time)

    # Check if the user's record exists in the table
    cursor.execute("SELECT lockout_timestamp FROM user_lockout WHERE user_id = %s", (user_id,))
    lockout_info = cursor.fetchone()

    if lockout_info:
        # Extract the lockout timestamp
        lockout_timestamp = lockout_info[0]

        if current_time > lockout_timestamp:
            # Reset failed login attempts to 0 and enable the user in Cognito
            cursor.execute("UPDATE user_lockout SET failed_login_attempts = 0 WHERE user_id = %s", (user_id,))
            conn.commit()

            client.admin_enable_user(
                UserPoolId=preprod_user_pool_id,
                Username=user_name
            )

    cursor.close()
    conn.close() 
    
 
    
def login_dev(user_name, decoded_password):
    user_id = dev_get_user_id(user_name)
    secret_hash = dev_get_secret_hash(user_name)
    client = boto3.client('cognito-idp',region_name='us-east-1')

    auth_parameters = {
        'USERNAME': user_name,
        'PASSWORD': decoded_password,
        'SECRET_HASH': secret_hash,
    }

    initiate_auth_params = {
        'UserPoolId': dev_user_pool_id,
        'ClientId': dev_client_id,
        'AuthFlow': 'ADMIN_USER_PASSWORD_AUTH',
        'AuthParameters': auth_parameters,
    }
    
    check_lockout_time_dev(user_name, user_id)

    try:
        admin_initiate_auth_response = client.admin_initiate_auth(**initiate_auth_params)
        print('admin_initiate_auth response:', admin_initiate_auth_response)
        trigger_post_auth(user_name, user_id)
        return admin_initiate_auth_response
        
    except botocore.exceptions.ClientError as e:
        # Handle the exception for incorrect credentials
        error_message = str(e)
        print(f"Authentication failed: {error_message}")
        
        # Trigger pre-auth Lambda and return the response
        pre_auth_response = trigger_pre_auth_dev(user_name, user_id)
        print('pre_auth_response:', pre_auth_response)
        return pre_auth_response
    
def login_uat(user_name, decoded_password):
    user_id = uat_get_user_id(user_name)
    secret_hash = uat_get_secret_hash(user_name)
    client = boto3.client('cognito-idp',region_name='us-east-1')

    auth_parameters = {
        'USERNAME': user_name,
        'PASSWORD': decoded_password,
        'SECRET_HASH': secret_hash,
    }

    initiate_auth_params = {
        'UserPoolId': uat_user_pool_id,
        'ClientId': uat_client_id,
        'AuthFlow': 'ADMIN_USER_PASSWORD_AUTH',
        'AuthParameters': auth_parameters,
    }
    
    check_lockout_time_uat(user_name, user_id)

    try:
        response = client.admin_initiate_auth(**initiate_auth_params)
        print('admin_initiate_auth response:', response)
        trigger_post_auth(user_name, user_id)
        return response
        
    except botocore.exceptions.ClientError as e:
        # Handle the exception for incorrect credentials
        error_message = str(e)
        print(f"Authentication failed: {error_message}")
        
        # Trigger pre-auth Lambda and return the response
        pre_auth_response = trigger_pre_auth_uat(user_name, user_id)
        print('pre_auth_response:', pre_auth_response)
        return pre_auth_response    
    
def login_mef(user_name, decoded_password):
    user_id = mef_get_user_id(user_name)
    secret_hash = mef_get_secret_hash(user_name)
    client = boto3.client('cognito-idp',region_name='us-east-1')

    auth_parameters = {
        'USERNAME': user_name,
        'PASSWORD': decoded_password,
        'SECRET_HASH': secret_hash,
    }

    initiate_auth_params = {
        'UserPoolId': uat_user_pool_id,
        'ClientId': uat_client_id,
        'AuthFlow': 'ADMIN_USER_PASSWORD_AUTH',
        'AuthParameters': auth_parameters,
    }
    
    check_lockout_time_mef(user_name, user_id)

    try:
        response = client.admin_initiate_auth(**initiate_auth_params)
        print('admin_initiate_auth response:', response)
        trigger_post_auth(user_name, user_id)
        return response
        
    except botocore.exceptions.ClientError as e:
        # Handle the exception for incorrect credentials
        error_message = str(e)
        print(f"Authentication failed: {error_message}")
        
        # Trigger pre-auth Lambda and return the response
        pre_auth_response = trigger_pre_auth_mef(user_name, user_id)
        print('pre_auth_response:', pre_auth_response)
        return pre_auth_response        
    
def login_preprod(user_name, decoded_password):
    user_id = preprod_get_user_id(user_name)
    secret_hash = preprod_get_secret_hash(user_name)
    client = boto3.client('cognito-idp',region_name='us-east-1')

    auth_parameters = {
        'USERNAME': user_name,
        'PASSWORD': decoded_password,
        'SECRET_HASH': secret_hash,
    }

    initiate_auth_params = {
        'UserPoolId': preprod_user_pool_id,
        'ClientId': preprod_client_id,
        'AuthFlow': 'ADMIN_USER_PASSWORD_AUTH',
        'AuthParameters': auth_parameters,
    }
    
    check_lockout_time_preprod(user_name, user_id)

    try:
        response = client.admin_initiate_auth(**initiate_auth_params)
        print('admin_initiate_auth response:', response)
        trigger_post_auth(user_name, user_id)
        return response
        
    except botocore.exceptions.ClientError as e:
        # Handle the exception for incorrect credentials
        error_message = str(e)
        print(f"Authentication failed: {error_message}")
        
        # Trigger pre-auth Lambda and return the response
        pre_auth_response = trigger_pre_auth_preprod(user_name, user_id)
        print('pre_auth_response:', pre_auth_response)
        return pre_auth_response
        

def validate_client(client_id, client_secret):
    
    message_bytes = base64.b64decode(client_id).decode("utf-8")
    username= message_bytes.split(":")[1]
    # decoded_password = base64.b64decode(client_secret).decode('ISO-8859-1')
    
    if len(client_secret) % 4 == 0:
        # If the length is already a multiple of 4, decode it directly
        print('inside if')
        decoded_password_bytes = base64.b64decode(client_secret.encode('ISO-8859-1'))
        decoded_password = decoded_password_bytes.decode('ISO-8859-1')
        
    #elif len(client_secret) % 4 != 0:    
    else:
        print("inside else")
        # Add padding characters to make it a valid Base64 string
        padded_client_secret = 'NkdvYk4zOSE='
        print('padded_client_secret', padded_client_secret)
    
        # Decode the padded value
        decoded_password_bytes = base64.b64decode(padded_client_secret.encode('ISO-8859-1'))
        decoded_password = decoded_password_bytes.decode('ISO-8859-1')
        
    print('Decoded Password:', decoded_password)
    print('after decode password')
    
    
    username_exists = False
    username1_exists = False
    username2_exists = False
    username3_exists = False
    
    dev_user_response = client.list_users(
    UserPoolId=dev_user_pool_id,
    )
    print('dev_user_response', dev_user_response)
    
    dev_usernames  = [user['Username'] for user in dev_user_response['Users']]
    print(dev_usernames, 'dev_usernames')
    
    for user in dev_usernames:
        if user == username.lower():
            username_exists = True
            break
    
    if username_exists:
        dev_response = login_dev(username, decoded_password)
        print(dev_response,'dev')
        print(type(dev_response['ResponseMetadata']['HTTPStatusCode']))
        dev_status_code  = dev_response['ResponseMetadata']['HTTPStatusCode']
        if dev_status_code == 200:
            print("success")
            return dev_response
        else:
            print('dev fail')
    
    
    else:
        uat_user_response = client.list_users(
        UserPoolId=uat_user_pool_id,
        )
    
        uat_usernames  = [user['Username'] for user in uat_user_response['Users']]
        print(type(uat_usernames),'uat_usernames')
    
        for user1 in uat_usernames:
            if user1 == username.lower():
                username1_exists = True
                break
        
        if username1_exists:
            print('inside uat funct')
            uat_response = login_uat(username, decoded_password)
            uat_status_code  = uat_response['ResponseMetadata']['HTTPStatusCode']
            print(uat_status_code,'status')
            if uat_status_code == 200:
                print('uat')
                print("uat")
                return uat_response
            else:
                print('fail uat')
                
        else:
            mef_user_response = client.list_users(UserPoolId=mef_user_pool_id)
            mef_usernames = [user['Username'] for user in mef_user_response['Users']]
            print(type(mef_usernames), 'mef_usernames')

            for user2 in mef_usernames:
                if user2 == username.lower():
                    username2_exists = True
                    break

            if username2_exists:
                print('inside mef funct')
                mef_response = login_mef(username, decoded_password)
                mef_status_code = mef_response['ResponseMetadata']['HTTPStatusCode']
                print(mef_status_code, 'status')
                if mef_status_code == 200:
                    print("mef")
                    return mef_response
                else:
                    print('fail mef')    
 
            else:
                preprod_user_response = client.list_users(UserPoolId=preprod_user_pool_id)
                preprod_usernames = [user['Username'] for user in preprod_user_response['Users']]
                print(type(preprod_usernames), 'preprod_usernames')

                for user3 in preprod_usernames:
                    if user3 == username.lower():
                        username3_exists = True
                        break

                if username3_exists:
                    print('inside preprod funct')
                    preprod_response = login_preprod(username, decoded_password)
                    preprod_status_code = preprod_response['ResponseMetadata']['HTTPStatusCode']
                    print(preprod_status_code, 'status')
                    if preprod_status_code == 200:
                        print("preprod")
                        return preprod_response
                    else:
                        print('fail preprod')
        
