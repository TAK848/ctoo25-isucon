# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is an ISUCON (Iikanjini Speed Up Contest) application called "Private ISU" - a photo-sharing social media platform similar to Instagram. The codebase is intentionally designed with performance bottlenecks for competition participants to identify and optimize.

## Common Development Commands

### Build and Run
```bash
# Build the Go application
cd golang/
make

# Run with Docker Compose (from root directory)
docker-compose up -d

# IMPORTANT: Switch to Go implementation in docker-compose.yml
# Change line 18: context: ruby/ → context: golang/

# NOTE: Docker設定（docker-compose.yml等）は本番環境と異なるため触らないでください
# NOTE: 本番はEC2で /home/isucon/private_isu/webapp/golang で動作、systemdでisuconユーザー権限で実行
```

### Database Operations
```bash
# Connect to MySQL
mysql -h 127.0.0.1 -P 3306 -u root -proot isuconp

# Initialize database (must complete within 10 seconds)
curl http://localhost/initialize

# View slow query log
docker-compose exec mysql tail -f /var/log/mysql/mysql-slow.log
```

### Performance Monitoring
```bash
# Go profiling endpoints
curl http://localhost/debug/pprof/
curl http://localhost/debug/fgprof?seconds=10

# Analyze access logs with alp
docker-compose logs nginx | alp ltsv --config alp-config.yaml
```

## Architecture Overview

### Tech Stack
- **Go**: Main application (golang/app.go)
- **MySQL 8.4**: Database with slow query logging enabled
- **Nginx**: Reverse proxy with LTSV logging
- **Memcached**: Session storage
- **Docker Compose**: Orchestration with resource limits (1 CPU, 1GB memory per service)

### Database Schema
- **users**: id, account_name, passhash, authority, del_flg, created_at
- **posts**: id, user_id, imgdata (BLOB), body, mime, created_at
- **comments**: id, post_id, user_id, comment, created_at

### Critical Performance Issues
1. **Images stored as BLOBs** in posts.imgdata column
2. **Missing indexes** on foreign keys (see commented code in app.go:1073-1076)
3. **N+1 queries** in makePosts function (partially fixed)
4. **Shell-based password hashing** using `openssl passwd -6`
5. **No caching** for image data or query results

### Key Endpoints
- `/initialize`: Database reset endpoint (10-second time limit)
- `/`: Main feed with pagination (20 posts per page)
- `/image/{id}.{ext}`: Image serving (major bottleneck)
- `/@{accountName}`: User profile pages
- `/posts/{id}`: Individual post pages
- `/admin/banned`: Admin functionality for banning users

### Environment Variables
```
ISUCONP_DB_HOST (default: localhost)
ISUCONP_DB_PORT (default: 3306)
ISUCONP_DB_USER (default: root)
ISUCONP_DB_PASSWORD (default: root)
ISUCONP_DB_NAME (default: isuconp)
ISUCONP_MEMCACHED_ADDRESS (default: localhost:11211)
```

## ISUCON Competition Requirements

### Validation Requirements
- All endpoints must maintain correct functionality
- CSRF tokens must be validated on POST requests
- Session-based authentication must work correctly
- Image types: JPEG, PNG, GIF only
- Maximum image size: 10MB
- DOM structure must not change
- JavaScript/CSS files must not be modified

### Scoring
- 1-minute benchmark runs
- Points based on successful HTTP requests
- Different request types have different point values
- Errors result in point deductions
- Data consistency must be maintained

### Common Optimization Strategies
1. Move image storage from database to filesystem
2. Add indexes: `posts(user_id)`, `posts(created_at)`, `comments(post_id)`, `comments(user_id)`
3. Implement in-memory caching for hot data
4. Replace shell-based password hashing with native Go crypto
5. Serve static files directly from nginx
6. Optimize database connection pooling
7. Batch queries to eliminate N+1 patterns

### Recent Optimizations in Code
- Fixed N+1 query in makePosts using batch comment counting (commits: 759ee4b)
- Added index on posts.created_at (commit: 4db0ba2)
- Database connection uses interpolateParams=true for better performance

## Important Notes
- **ファイルの最終行には必ず改行を入れてください** - POSIX標準に準拠し、gitでの差分表示を見やすくするため