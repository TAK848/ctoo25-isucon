# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is an ISUCON (Iikanjini Speed Up Contest) application called "Private ISU" - a photo-sharing social media platform similar to Instagram. The codebase is intentionally designed with performance bottlenecks for competition participants to identify and optimize.

## Common Development Commands

### Build and Run
```bash
# Build the application
make

# Run with Docker Compose (from parent directory)
cd ..
docker-compose up -d

# Switch to Go implementation in docker-compose.yml
# Change line 18: context: ruby/ → context: golang/
```

### Database Operations
```bash
# Connect to MySQL
mysql -h 127.0.0.1 -P 3306 -u root -proot isuconp

# Initialize database (clears all data)
curl http://localhost/initialize
```

### Performance Monitoring
```bash
# Access pprotein debug endpoints
curl http://localhost/debug/pprof/
curl http://localhost/debug/fgprof?seconds=10
```

## Architecture Overview

### Core Components
1. **app.go**: Main application with all HTTP handlers, database models, and business logic
2. **MySQL**: Stores users, posts, comments, and image data (images stored as BLOBs in database)
3. **Memcached**: Session storage using gorilla-sessions-memcache
4. **Nginx**: Reverse proxy on port 80, routes to Go app

### Key Performance Considerations
- Images are stored in the `posts.imgdata` BLOB column (potential optimization point)
- Password hashing uses shell commands to OpenSSL (`openssl passwd -6`)
- N+1 query patterns in `makePosts` function when fetching comment counts
- No indexes on foreign keys (see commented index creation in app.go:1073-1076)
- All image processing happens in the application layer

### Critical Endpoints
- `/initialize`: Must complete within 10 seconds for benchmarking
- `/`: Main feed with pagination
- `/image/{id}.{ext}`: Image serving (major traffic source)
- `/@{accountName}`: User profiles with their posts

### Environment Variables
- `ISUCONP_DB_HOST`: MySQL host (default: localhost)
- `ISUCONP_DB_PORT`: MySQL port (default: 3306)
- `ISUCONP_DB_USER`: MySQL user (default: root)
- `ISUCONP_DB_PASSWORD`: MySQL password (default: root)
- `ISUCONP_DB_NAME`: Database name (default: isuconp)
- `ISUCONP_MEMCACHED_ADDRESS`: Memcached address (default: localhost:11211)

## ISUCON-Specific Notes

### Validation Requirements
- All endpoints must return correct data and status codes
- CSRF tokens must be properly validated on POST requests
- Image types limited to JPEG, PNG, GIF
- Maximum image size: 10MB
- User authentication must be maintained via sessions

### Common Optimization Strategies
1. Move image storage from database to filesystem/CDN
2. Add proper database indexes
3. Implement query result caching
4. Optimize N+1 queries with JOIN or batch fetching
5. Replace shell-based password hashing with native Go implementation
6. Implement connection pooling and query optimization

### Debugging Tools
- pprotein integration available at `/debug/*` endpoints
- Use `/debug/pprof/` for standard Go profiling
- Use `/debug/fgprof` for full goroutine profiling