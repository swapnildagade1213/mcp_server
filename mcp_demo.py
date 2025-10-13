# server.py
from fastmcp import FastMCP
import requests 
from typing import Any, Dict
from datetime import datetime
import jwt
import os
import dotenv
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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

@mcp.tool()
def greet_me()-> str:
    return "Hello $w@Pn!L D@G@De !!!"

@mcp.tool()
def fetch_clientId(saltdata : str, keydata : str)-> str:
    try:
        cid = "Z0FBQUFBQm83SlZyeURnNFY3UkZPb1ZjWDd5MThaVWc5WG43VEZNSVZpdVVzR2JMOEFKUWl3Y0lmcXg0T1ByWXpRVExEOFdnNEJ2TXZadmVwTFhjcWgzLVdVb1JONkl3YU5LZEhxMjEtbkxDYTdIaGZmRVBZZm9tckZMWWRIQmJFaloyYktzdXVVMWI="
        encrypted_data = base64.urlsafe_b64decode(cid)
        salt = base64.urlsafe_b64decode(saltdata)
        key, _ = generate_key_from_password(keydata, salt)
        decrypted_clientId = decrypt_text(encrypted_data, key)
        return decrypted_clientId
    except Exception as e:
        return "Decryption error"


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
