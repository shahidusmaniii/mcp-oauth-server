import requests
import json
from . import config

def fetch_weather(city: str) -> str:
    """
    Fetches the current weather for a specified city using the OpenWeatherMap API.
    Use this tool when a user asks for weather information.
    The city parameter should be a valid city name (e.g., 'London', 'Tokyo').
    """
    base_url = "https://api.openweathermap.org/data/2.5/weather"
    params = {
        "q": city,
        "appid": config.WEATHER_API_KEY,
        "units": "metric"
    }
    try:
        response = requests.get(base_url, params=params)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        return json.dumps(response.json())
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 404:
            return f"Error: Could not find weather data for '{city}'. It might be a misspelled or invalid city."
        return f"Error: An HTTP error occurred: {http_err}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"

