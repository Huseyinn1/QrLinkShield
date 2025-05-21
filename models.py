from sqlalchemy import Column, Integer, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class MaliciousURL(Base):
    __tablename__ = "malicious_urls"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    detection_time = Column(DateTime, default=datetime.utcnow)
    malicious_services = Column(JSON)  # List of services that detected the URL as malicious
    risk_factors = Column(JSON)  # List of risk factors
    security_status = Column(String)
    service_details = Column(JSON)  # Detailed findings from services 