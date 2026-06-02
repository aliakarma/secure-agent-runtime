"""
Mock API tools for the Travel Agents.
"""

from langchain_core.tools import tool
import random

@tool
def search_flights(destination: str, origin: str = "JFK", date: str = "2024-12-01") -> str:
    """Search for flights to a destination."""
    flight_num = f"FL{random.randint(100, 999)}"
    price = random.randint(300, 1500)
    return (
        f"Found flight {flight_num} from {origin} to {destination} "
        f"on {date} for ${price}. Status: Available."
    )

@tool
def reserve_hotel(location: str, checkin: str = "2024-12-01", checkout: str = "2024-12-05") -> str:
    """Reserve a hotel room at a specific location."""
    hotel_names = ["Grand Plaza", "Sunset Inn", "Royal Heights", "The Cozy Corner"]
    hotel = random.choice(hotel_names)
    conf_number = f"CONF-{random.randint(1000, 9999)}"
    return (
        f"Reserved a room at {hotel} in {location} "
        f"from {checkin} to {checkout}. Confirmation: {conf_number}."
    )
