# weather_server.py
...

# weather_server.py
from typing import List
from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv
import requests 
import os 

from datetime import datetime
from typing import Any, Dict, Optional, Union 
mcp = FastMCP("Weather")

@mcp.tool()
async def get_weather(city: str) -> Dict[str, Any]:
    """Get weather information for a city.
    
    Args:
        city: Any city name, not limited to Indian cities
        
    Returns:
        Weather data for the requested city
    """
    api_key = os.getenv("OPENWEATHER_API_KEY", "9714c902c784730338c95bd3140cc6ed")
    units = os.getenv("WEATHER_UNITS", "metric")  # Use metric by default for Celsius
    
    try:
        
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
        
    except requests.exceptions.RequestException as e:
        return {"error": f"Failed to fetch weather data: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

if __name__ == "__main__":
    mcp.run(transport="stdio")
