# server.py
from fastmcp import FastMCP
import requests 
from typing import Any, Dict 
import jwt
import os
import dotenv
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC 
import json

from exchangelib import  OAuth2Credentials, Configuration, Account, IMPERSONATION,Identity, Q
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter
from msal import ConfidentialClientApplication
from datetime import datetime, timedelta, timezone 


dotenv.load_dotenv()
mcp = FastMCP("My MCP Server")

def generate_key_from_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    if isinstance(password, str):
        password = password.encode()        
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key, salt

def encrypt_text(text, key):
    if isinstance(text, str):
        text = text.encode()
    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(text)
    return encrypted_text

def decrypt_text(encrypted_text, key):
    cipher = Fernet(key)
    decrypted_text = cipher.decrypt(encrypted_text)
    return decrypted_text.decode()

def get_DecryptedText(encrypted_text,salt_b64,password) :
    salt = base64.urlsafe_b64decode(salt_b64)
    key, _ = generate_key_from_password(password, salt)
    encrypted_data = base64.urlsafe_b64decode(encrypted_text)
    decrypted_data = decrypt_text(encrypted_data, key)
    return decrypted_data

def fetch_graphToken(saltdata : str, keydata : str)-> str:
    """
    Fetch Graph Token
    
    Args:
        saltdata (str): saltdata
        keydata (str): keydata      
        
    Returns:
        str: JWTToken
    """
    client_id = "Z0FBQUFBQm83Y3JUUUFTd1JUN3A2YndQa2JCdHZadDhlUV8zcmZPYWc2ZnFkSlNEWlRqc1hjeEVpSE0wZzNPTlVUU0h2Uk0xMzNjaDdIN2EzR3M0Rm5uM0ZEUVU0NTYwc2xwUUR1OVBqQ2o0UHFfTFdONjdNOEFDczRwVjFNakpnTnNWaHRjNlVPbGQ="
    client_secret = "Z0FBQUFBQm83Y3JURk9VZHZ1OXJpLWdmQmZ4RWs5dzhhMWZSMzRDT0puSHZsdnlmcm9wOHY3OE9ON2xYeWhOSmhzTUxOVXhIbDI3cmYxS1F0LV81OFcwd3ByUnNoelJIc0l3UGpncFB6MmVXYmtSbjluejIyVzQwLU1abXZEUmh6b0FaRC1nQ2p5LU0="
    tenant_id = "Z0FBQUFBQm83Y3JUelJ5d1pFTDE0c3MzWWgyd0FpXzNoLS1nZE45Q0psREpDYmI5SFlNSm1zd0dzdUFDWERhdndDYWRYdTBjMkRLa0NKQU91NVYxU2lYZ1VLaDg3NTJDekhWQzNiY0ZjRHpGbUZ2TktXZmdXNWpJUkJJX2IwbXI3a3A2U1I5LVdoUDA="
    client_id = get_DecryptedText(client_id,saltdata,keydata)
    client_secret = get_DecryptedText(client_secret,saltdata,keydata)
    tenant_id = get_DecryptedText(tenant_id,saltdata,keydata)
    authority = f'https://login.microsoftonline.com/{tenant_id}'
    scope = ['https://graph.microsoft.com/.default']
    app = ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret
    )
    token_response = app.acquire_token_for_client(scopes=scope)
    if 'access_token' in token_response:
        return f"{token_response['access_token']}"
    else:
        return f"Token not reterived"

@mcp.tool()
def get_companycode()-> str:
    """
    Fetch company code
    
    Args: None
        
    Returns:
        str: company code
    """
    return "#123"

@mcp.tool()
async def get_userUpcomingMeetings(email: str, saltdata : str, keydata : str ) -> str:
    """Get upcoming meetings of a user for the next specified days.

    Returns:
        Upcoming meetings of the user for the next specified days.
    """ 

    client_id = "Z0FBQUFBQnBBZExWcGxja25NVk11QjdTbWVIS0VrTFRxSms2RTM5UTA2ell5ZGp2UHdTNXlvbTJ4MGx6NkZ4aVNJSXF4bm9ZRDVReXBkQ1B2dFpqVHBJNjlGaWZhYWFhdm8zRzk0aWdrZl82MnVIaTVPMU5JMlJnN1gzLWhjbkpJTlhQam9vc04zeHU="
    client_secret = "Z0FBQUFBQnBBZExWZ0Q0em1Tci1IU2VhUTJNS2dJaUxTZ0Mxb2RubXpLeUNNMWNxOFZHSDI2TUdhMktEMmJid1NWWVVqeXBub21NellCZ3VHVHBOeGgxeVRCeGlnMURjUTRwZGdBcm5velpJaUsxVmVON3hPT0sxWXNOdlRJR01ubnllVVVRYU45eWk="
    tenant_id = "Z0FBQUFBQnBBZExWdkJhSnI3V0lJbWN6OHc3QVJqRFZ6Z1dsYWptenpRVHJLNWhTZUlMSGRLRUsza1BEci1DakdjLUhGRDdpR0F2azFkaWFPWWo2SUZ5cjVwTXF2X3RpWUNxTjdHWHVNRWlvRnRsNy1hOTd4RFZzRHo5LU9hel9seWZiZlVyaEtBMVk="
    client_id = get_DecryptedText(client_id,saltdata,keydata)
    client_secret = get_DecryptedText(client_secret,saltdata,keydata)
    tenant_id = get_DecryptedText(tenant_id,saltdata,keydata)
    authority = f'https://login.microsoftonline.com/{tenant_id}'
    scope = ['https://outlook.office365.com/.default']

    # Target mailbox to impersonate 
    # Get access token using MSAL
    app = ConfidentialClientApplication(
        client_id=client_id,
        authority=authority,
        client_credential=client_secret,
    )
    token_response = app.acquire_token_for_client(scopes=scope)
    if 'access_token' in token_response:
        return f"{token_response['access_token']}"
    else:
        return f"Token not reterived"
    
    credentials = OAuth2Credentials(client_id=client_id, client_secret=client_secret, tenant_id=tenant_id, identity=Identity(primary_smtp_address=email))
    config = Configuration(credentials=credentials, server='outlook.office365.com', auth_type='OAuth 2.0')
    account = Account(primary_smtp_address=email, config=config, autodiscover=False, access_type=IMPERSONATION)

    start = datetime.now(timezone.utc)
    end = start + timedelta(days=2)

    calendar_items = account.calendar.view(start=start, end=end).only('subject')
    meetings = []
    for item in calendar_items:
        meetings.append({
            "subject": item.subject
        })
    return json.dumps(meetings)

@mcp.tool()
def get_employeePresence(employeeId : str, saltdata : str, keydata : str)-> Dict[str, Any]:
    """
    Fetch Employee Info
    
    Args:
        employeeId (str): employeeId
        saltdata (str): saltdata
        keydata (str): keydata
        
    Returns:
        str: Employee Info
    """
    jwtToken = fetch_graphToken(saltdata,keydata)
    headers = {
        'Authorization': f"Bearer {jwtToken}",
        'Content-Type': 'application/json'
    }
    get_user_url = f"https://graph.microsoft.com/v1.0/users?$filter=employeeid eq '{employeeId}'"  
    response = requests.get(get_user_url, headers=headers)
    user_data = response.json()
    user_id = user_data.get("value", [{}])[0].get("id")
    presence_endpoint = 'https://graph.microsoft.com/v1.0/users/{user_id}/presence'  
    response = requests.get(presence_endpoint.replace("{user_id}", user_id), headers=headers)
    presence_data = response.json()
    formatted_presence_data = {
        "Display Name": user_data.get("value", [{}])[0].get("displayName"),
        "Is Out Of Office": presence_data.get("outOfOfficeSettings", {}).get("isOutOfOffice"),
        "Availability": presence_data.get("availability"),
        "Activity": presence_data.get("activity"),
    }
    return formatted_presence_data


@mcp.tool()
def get_employeeInfo(employeeId : str, saltdata : str, keydata : str)-> str:
    """
    Fetch Employee Info
    
    Args:
        employeeId (str): employeeId
        saltdata (str): saltdata
        keydata (str): keydata
        
    Returns:
        str: Employee Info
    """
    jwtToken = fetch_graphToken(saltdata,keydata)
    headers = {
        'Authorization': f"Bearer {jwtToken}",
        'Content-Type': 'application/json'
    }
    get_user_url = f"https://graph.microsoft.com/v1.0/users?$filter=employeeid eq '{employeeId}'"  
    response = requests.get(get_user_url, headers=headers)
    user_data = response.json()
    return json.dumps(user_data.get("value", [{}])[0])

@mcp.tool()
def get_branches(username: str , token: str , repo_name : str) -> list:
    """
    Fetch GitHub branches for a given repository.
    
    Args:
        username (str): GitHub username
        token (str): GitHub authentication token
        repo_name (str): Repository name
        
    Returns:
        list: List of branches data or None if request fails
    """
    # GitHub API endpoint
    url = f"https://api.github.com/repos/{username}/{repo_name}/branches"
    
    # Make request
    response = requests.get(url, auth=(username, token), verify=False)
    
    if response.status_code == 200:
        data = response.json()
        repo_urls = []
        for repo in data:
            repo_urls.append(repo["name"])  # Using html_url instead of API url
        return repo_urls
    else:
        return(f"Failed to retrieve branches: {response.status_code}")
        
@mcp.tool()
def get_repositories(username: str , token: str ) -> list:
    """
    Fetch GitHub repositories for a given username.
    
    Args:
        username (str): GitHub username
        token (str): GitHub authentication token
        
    Returns:
        list: List of repositories data or None if request fails
    """
    # GitHub API endpoint
    url = f"https://api.github.com/users/{username}/repos"
    
    # Make request
    response = requests.get(url, auth=(username, token), verify=False)
    
    if response.status_code == 200:
        data = response.json()
        repo_urls = []
        for repo in data:
            repo_urls.append(repo["html_url"])  # Using html_url instead of API url
        return repo_urls
    else:
        return(f"Failed to retrieve repositories: {response.status_code}")



@mcp.tool()
async def decode_jwttoken(jwt_token: str) -> str:
    """Decode a JWT token without signature verification.
    
    This function decodes the provided JWT token and returns its contents as a formatted string.
    Note that signature verification is intentionally disabled, so this should only be used for
    inspection purposes, not for authentication validation.
    
    Args:
        jwt_token: A string containing the JWT token to be decoded.
        
    Returns:
        str: A formatted string with each claim on a new line in "key: value" format.
        
    Raises:
        jwt.exceptions.DecodeError: If the token is malformed or invalid.
    """
    # Decode without verifying the signature
    decoded = jwt.decode(jwt_token, options={"verify_signature": False})
    return '\n'.join([f"{key}: {value}" for key, value in decoded.items()])
    
@mcp.tool()
async def get_weather(city: str) -> Dict[str, Any]:
    """Get weather information for a city.
    
    Args:
        city: Any city name, not limited to Indian cities
        
    Returns:
        Weather data for the requested city 
    """

    units = "metric"
    api_key = "9714c902c784730338c95bd3140cc6ed"
        
    url = (
        f"https://api.openweathermap.org/data/2.5/weather"
        f"?q={city}&units={units}&appid={api_key}"
    )
    
    response = requests.get(
        url, 
        timeout=30.0, 
        verify=False
    )
    
    response.raise_for_status()
    
    # Parse and format the weather data
    weather_data = response.json()
    
    # Format the response for better readability
    formatted_data = {
        "location": f"{weather_data.get('name', city)}, {weather_data.get('sys', {}).get('country', 'Unknown')}",
        "temperature": {
            "current": weather_data.get('main', {}).get('temp'),
            "feels_like": weather_data.get('main', {}).get('feels_like'),
            "min": weather_data.get('main', {}).get('temp_min'),
            "max": weather_data.get('main', {}).get('temp_max')
        },
        "humidity": weather_data.get('main', {}).get('humidity'),
        "wind": {
            "speed": weather_data.get('wind', {}).get('speed'),
            "direction": weather_data.get('wind', {}).get('deg')
        },
        "description": weather_data.get('weather', [{}])[0].get('description', 'Unknown'),
        "timestamp": datetime.now().isoformat()
    }
    return formatted_data

if __name__ == "__main__":
     mcp.run()
