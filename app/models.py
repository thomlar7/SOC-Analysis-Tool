from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.sqlite import JSON

db = SQLAlchemy()

class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    risk_category = db.Column(db.String(50), index=True)
    risk_score = db.Column(db.String(50))
    action_required = db.Column(db.Text)
    mitre_analysis = db.Column(JSON)
    
    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'timestamp': self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            'risk_category': self.risk_category,
            'risk_score': self.risk_score,
            'action_required': self.action_required,
            'mitre_analysis': self.mitre_analysis
        }
  