"""Format weather data for display."""

def format_weather(data):
    """Take weather dict and return human-readable string."""
    temp = data.get("temperature", "N/A")
    condition = data.get("condition", "unknown")
    return f"Currently {temp}°F and {condition}"

if __name__ == "__main__":
    sample = {"temperature": 72, "condition": "sunny"}
    print(format_weather(sample))
