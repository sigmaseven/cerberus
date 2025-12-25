@echo off
REM ML Database Setup Script for Cerberus
REM This script creates the necessary MongoDB collections for ML functionality

echo Setting up ML collections in MongoDB...

REM Connect to MongoDB and create collections
mongosh --eval "
db = db.getSiblingDB('cerberus');

// Create ML collections
db.createCollection('ml_models');
db.createCollection('ml_features');
db.createCollection('ml_training_history');
db.createCollection('ml_feedback');

// Create indexes for performance
db.ml_models.createIndex({ 'algorithm': 1, 'version': 1 });
db.ml_models.createIndex({ 'created_at': -1 });

db.ml_features.createIndex({ 'event_id': 1 });
db.ml_features.createIndex({ 'timestamp': -1 });

// TTL index for features (24 hours)
db.ml_features.createIndex({ 'timestamp': 1 }, { expireAfterSeconds: 86400 });

db.ml_training_history.createIndex({ 'timestamp': -1 });
db.ml_training_history.createIndex({ 'algorithm': 1 });

db.ml_feedback.createIndex({ 'event_id': 1 });
db.ml_feedback.createIndex({ 'timestamp': -1 });
db.ml_feedback.createIndex({ 'analyst_id': 1 });

print('ML collections created successfully');
print('Collections:');
db.getCollectionNames().forEach(function(coll) {
    if (coll.startsWith('ml_')) {
        print('  - ' + coll);
    }
});
"