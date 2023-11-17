import json
from app.controller.user_management import validate_client
from fastapi import FastAPI, Header, HTTPException,Request

app = FastAPI()



def validate(headers):
    try:
        print("Received Headers:", headers)
        
        client_id = headers.get("clientid")
        client_secret = headers.get("clientsecret")
        
        if not client_id or not client_secret:
            raise ValueError("Missing client credentials in headers")
        
        response = validate_client(client_id, client_secret)
        print(response)
        
        authentication_result= response.get("AuthenticationResult", {})
        
        if not authentication_result:
            return {
                'message': 'User is locked, try after sometime'
            }
        
        access_token = authentication_result.get("AccessToken")
        expires_in = authentication_result.get("ExpiresIn")
        token_type = authentication_result.get("TokenType")
        refresh_token = authentication_result.get("RefreshToken")
        id_token = authentication_result.get("IdToken")
        
        response_json = {
                'message': 'Validation successful',
                'data': {
                'AccessToken': id_token,
                'ExpiresIn': expires_in,
                'TokenType' : token_type,
                'RefreshToken' : refresh_token
                
            }
        }
        
        return response_json    
        
    except Exception as e:
        print("Error:", str(e))
        return {
            'statusCode': 500,
            'body': json.dumps('Cannot Validate')
        }

@app.post("/ec2/api/oauth/token")
async def validate_token(headers: Request):
    try:
        # authorization = headers.headers.get('Authorization')
        # if not authorization:
        #     raise Exception('Missing Authorization header')
        
        headers_dict = headers.headers
        print(headers_dict,'headers')
        result = validate(headers_dict)
        print(json.dumps(result))
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# def lambda_handler(event, context):
#     print(event)  # Print the event object to CloudWatch logs
    
#     request_path = event["request_uri"]  # Extract the request path from Kong's event structure
#     headers = event["request_headers"]  # Extract request headers
    
#     if "/ec2/api/oauth/token" in request_path:
#         result = validate(headers)  # Pass headers directly to the function
#         print(json.dumps(result))  # Print the JSON response
#         return result


    