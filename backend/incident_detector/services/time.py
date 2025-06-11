
import logging


logger = logging.getLogger(__name__)

def format_timedelta(delta):

    """
    Converts a timedelta object into a short  string.
    
    Parameters:
        delta (timedelta): The timedelta object to format.
    
    Returns:
        str: a string of minutes and seconds.
    """
    seconds = int(delta.total_seconds())
    minutes, seconds = divmod(seconds, 60)
    if minutes and seconds:
        return f"{minutes} minutes and {seconds} seconds"
    elif minutes:
        return f"{minutes} minutes"
    else:
        return f"{seconds} seconds"
