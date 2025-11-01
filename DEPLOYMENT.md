# Cerberus SIEM Deployment Guide

This guide provides instructions for deploying the Cerberus SIEM system in various environments.

## Architecture Overview

Cerberus consists of three main components:
- **Frontend**: React-based web interface served by Nginx
- **Backend**: Go-based API server and event processing engine
- **Database**: MongoDB for data persistence

## Prerequisites

- Docker and Docker Compose
- At least 4GB RAM and 2 CPU cores
- Ports 514, 515, 8080, 8081, 3000, and 27017 available

## Quick Start with Docker Compose

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd cerberus
   ```

2. **Configure the application:**
   ```bash
   # Copy and modify configuration files
   cp config.yaml.example config.yaml
   cp rules.yaml.example rules.yaml
   cp correlation_rules.json.example correlation_rules.json
   ```

3. **Start the services:**
   ```bash
   docker-compose up -d
   ```

4. **Access the application:**
   - Frontend: http://localhost:3000
   - API: http://localhost:8081
   - Health check: http://localhost:8081/health

## Manual Deployment

### Backend Deployment

1. **Build the Go binary:**
   ```bash
   go build -o cerberus .
   ```

2. **Configure environment variables:**
   ```bash
   export CERBERUS_MONGODB_URI=mongodb://localhost:27017
   export CERBERUS_MONGODB_DATABASE=cerberus
   ```

3. **Run the backend:**
   ```bash
   ./cerberus
   ```

### Frontend Deployment

1. **Build the frontend:**
   ```bash
   cd frontend
   npm install
   npm run build
   ```

2. **Serve with Nginx:**
   ```bash
   # Copy dist files to nginx html directory
   sudo cp -r dist/* /usr/share/nginx/html/

   # Copy nginx configuration
   sudo cp nginx.conf /etc/nginx/sites-available/cerberus
   sudo ln -s /etc/nginx/sites-available/cerberus /etc/nginx/sites-enabled/

   # Restart nginx
   sudo systemctl restart nginx
   ```

## Production Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CERBERUS_MONGODB_URI` | MongoDB connection URI | `mongodb://localhost:27017` |
| `CERBERUS_MONGODB_DATABASE` | Database name | `cerberus` |
| `CERBERUS_LOG_LEVEL` | Logging level | `info` |
| `CERBERUS_PORT` | API server port | `8081` |

### Security Considerations

1. **Network Security:**
   - Use firewalls to restrict access to required ports only
   - Consider using reverse proxies for additional security

2. **Database Security:**
   - Enable MongoDB authentication
   - Use TLS for database connections
   - Regularly backup data

3. **Application Security:**
   - Keep dependencies updated
   - Use HTTPS in production
   - Implement proper authentication/authorization

### Performance Tuning

1. **MongoDB:**
   - Configure appropriate indexes
   - Monitor database performance
   - Consider sharding for high-volume deployments

2. **Backend:**
   - Adjust worker pool sizes based on CPU cores
   - Configure appropriate buffer sizes
   - Monitor memory usage

3. **Frontend:**
   - Enable gzip compression
   - Configure appropriate cache headers
   - Use CDN for static assets

## Monitoring and Maintenance

### Health Checks

The application provides health check endpoints:
- Backend: `GET /health`
- Frontend: `GET /health`

### Logs

- Backend logs are written to stdout/stderr
- Configure log aggregation (ELK stack, etc.)
- Set up log rotation

### Backups

```bash
# Database backup
docker exec cerberus_mongo mongodump --db cerberus --out /backup

# Configuration backup
cp config.yaml config.yaml.backup
cp rules.yaml rules.yaml.backup
```

## Troubleshooting

### Common Issues

1. **Port conflicts:**
   - Check if required ports are available
   - Use `netstat -tlnp` to identify conflicts

2. **Database connection issues:**
   - Verify MongoDB is running
   - Check connection string
   - Review MongoDB logs

3. **Frontend not loading:**
   - Check nginx configuration
   - Verify build artifacts exist
   - Check browser console for errors

### Debug Mode

Enable debug logging:
```bash
export CERBERUS_LOG_LEVEL=debug
```

## Scaling

### Horizontal Scaling

1. **Load Balancer:**
   - Use nginx or HAProxy for load balancing
   - Configure session affinity if needed

2. **Database:**
   - Use MongoDB replica sets
   - Consider sharding for large datasets

### Vertical Scaling

- Increase CPU/memory based on load
- Monitor resource usage
- Adjust buffer sizes accordingly

## Support

For issues and questions:
- Check the logs for error messages
- Review configuration files
- Test with minimal configuration
- Create an issue in the project repository

## License

This project is licensed under the MIT License.