// MongoDB authentication setup script
db = db.getSiblingDB('cerberus');

// Create application user with read/write access to cerberus database
db.createUser({
  user: 'cerberus_app',
  pwd: 'app_password_456',
  roles: [
    {
      role: 'readWrite',
      db: 'cerberus'
    }
  ]
});

// Create user for the application to use
// This user has limited privileges compared to the admin user
db.createUser({
  user: 'cerberus_user',
  pwd: 'user_password_789',
  roles: [
    {
      role: 'readWrite',
      db: 'cerberus'
    }
  ]
});