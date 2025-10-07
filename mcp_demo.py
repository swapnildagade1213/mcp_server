# server.py
from fastmcp import FastMCP
import requests 
from typing import Any, Dict
from datetime import datetime
import jwt

mcp = FastMCP("My MCP Server")
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
    api_key = "9714c902c784730338c95bd3140cc6ed"
    units = "metric"
        
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
