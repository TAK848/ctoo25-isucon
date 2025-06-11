package main

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	gsm "github.com/bradleypeabody/gorilla-sessions-memcache"
	"github.com/catatsuy/private-isu/webapp/golang/chiinteg"
	"github.com/go-chi/chi/v5"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
	"github.com/samber/lo"
	"github.com/samber/lo/mutable"
)

var (
	db             *sqlx.DB
	store          *gsm.MemcacheStore
	memcacheClient *memcache.Client
	templates      map[string]*template.Template
)

const (
	postsPerPage  = 20
	ISO8601Format = "2006-01-02T15:04:05-07:00"
	UploadLimit   = 10 * 1024 * 1024                        // 10mb
	ImageDir      = "/home/isucon/private_isu/webapp/image" // isuconユーザー権限で書き込み可能なディレクトリ
)

type User struct {
	ID          int       `db:"id"`
	AccountName string    `db:"account_name"`
	Passhash    string    `db:"passhash"`
	Authority   int       `db:"authority"`
	DelFlg      int       `db:"del_flg"`
	CreatedAt   time.Time `db:"created_at"`
}

type Post struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	Imgdata      []byte    `db:"imgdata"`
	Body         string    `db:"body"`
	Mime         string    `db:"mime"`
	CreatedAt    time.Time `db:"created_at"`
	CommentCount int
	Comments     []Comment
	User         User
	CSRFToken    string
}

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
	User      User
}

func init() {
	memdAddr := os.Getenv("ISUCONP_MEMCACHED_ADDRESS")
	if memdAddr == "" {
		memdAddr = "localhost:11211"
	}
	memcacheClient = memcache.New(memdAddr)
	memcacheClient.Timeout = 100 * time.Millisecond // Set shorter timeout

	// Test memcached connection
	testKey := "test_connection"
	err := memcacheClient.Set(&memcache.Item{
		Key:        testKey,
		Value:      []byte("test"),
		Expiration: 1,
	})
	if err != nil {
		log.Fatalf("Failed to connect to memcached at %s: %v", memdAddr, err)
	}

	// Clean up test key
	memcacheClient.Delete(testKey)

	store = gsm.NewMemcacheStore(memcacheClient, "iscogram_", []byte("sendagaya"))
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

func initTemplates() {
	templates = make(map[string]*template.Template)

	fmap := template.FuncMap{
		"imageURL": func(p Post) string {
			ext := ""
			if p.Mime == "image/jpeg" {
				ext = ".jpg"
			} else if p.Mime == "image/png" {
				ext = ".png"
			} else if p.Mime == "image/gif" {
				ext = ".gif"
			}
			return "/image/" + strconv.Itoa(p.ID) + ext
		},
	}

	// Login page
	templates["login"] = template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("login.html"),
	))

	// Register page
	templates["register"] = template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("register.html"),
	))

	// Index page
	templates["index"] = template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("index.html"),
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	))

	// User page
	templates["user"] = template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("user.html"),
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	))

	// Posts partial
	templates["posts"] = template.Must(template.New("posts.html").Funcs(fmap).ParseFiles(
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	))

	// Post detail page
	templates["post_id"] = template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("post_id.html"),
		getTemplPath("post.html"),
	))

	// Admin banned page
	templates["banned"] = template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("banned.html"),
	))
}

// 画像をオンデマンドで保存
func saveImageToFile(id int, mime string, imgdata []byte) error {
	// 画像ディレクトリが存在しない場合は作成
	if err := os.MkdirAll(ImageDir, 0755); err != nil {
		return fmt.Errorf("failed to create image directory: %w", err)
	}

	// 拡張子を決定
	ext := ""
	switch mime {
	case "image/jpeg":
		ext = ".jpg"
	case "image/png":
		ext = ".png"
	case "image/gif":
		ext = ".gif"
	default:
		return fmt.Errorf("unknown mime type: %s", mime)
	}

	// ファイルパスを生成
	filename := fmt.Sprintf("%d%s", id, ext)
	imagePath := filepath.Join(ImageDir, filename)

	// ファイルに書き込み
	if err := os.WriteFile(imagePath, imgdata, 0644); err != nil {
		return fmt.Errorf("failed to write image file: %w", err)
	}

	return nil
}

func tryLogin(accountName, password string) *User {
	u := User{}
	err := db.Get(&u, "SELECT * FROM users WHERE account_name = ? AND del_flg = 0", accountName)
	if err != nil {
		return nil
	}

	if calculatePasshash(u.AccountName, password) == u.Passhash {
		return &u
	} else {
		return nil
	}
}

func validateUser(accountName, password string) bool {
	return regexp.MustCompile(`\A[0-9a-zA-Z_]{3,}\z`).MatchString(accountName) &&
		regexp.MustCompile(`\A[0-9a-zA-Z_]{6,}\z`).MatchString(password)
}

func digest(src string) string {
	h := sha512.New()
	h.Write([]byte(src))
	return hex.EncodeToString(h.Sum(nil))
}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

func getSession(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isuconp-go.session")

	return session
}

func getSessionUser(r *http.Request) User {
	session := getSession(r)
	uid, ok := session.Values["user_id"]
	if !ok || uid == nil {
		return User{}
	}

	// Handle both int and int64
	var userID int
	switch v := uid.(type) {
	case int:
		userID = v
	case int64:
		userID = int(v)
	default:
		return User{}
	}
	cacheKey := fmt.Sprintf("user:%d", userID)

	// Check memcached first
	item, err := memcacheClient.Get(cacheKey)
	if err == nil {
		var u User
		if err := json.Unmarshal(item.Value, &u); err == nil {
			return u
		}
	}

	// Not in cache, fetch from DB
	u := User{}
	err = db.Get(&u, "SELECT * FROM `users` WHERE `id` = ?", userID)
	if err != nil {
		return User{}
	}

	// Cache the user in memcached (1 hour expiration)
	if data, err := json.Marshal(u); err == nil {
		memcacheClient.Set(&memcache.Item{
			Key:        cacheKey,
			Value:      data,
			Expiration: 3600, // 1 hour
		})
	}

	return u
}

func getFlash(w http.ResponseWriter, r *http.Request, key string) string {
	session := getSession(r)
	value, ok := session.Values[key]

	if !ok || value == nil {
		return ""
	} else {
		delete(session.Values, key)
		session.Save(r, w)
		return value.(string)
	}
}

func makePosts(results []Post, csrfToken string, fetchAllComments bool) ([]Post, error) {
	results = lo.Filter(results, func(p Post, _ int) bool {
		return p.User.ID == 0 || (p.User.ID != 0 && p.User.DelFlg == 0)
	})
	if len(results) > postsPerPage {
		results = results[:postsPerPage]
	}

	if len(results) == 0 {
		return []Post{}, nil
	}

	// Extract post IDs
	postIDs := lo.Map(results, func(p Post, _ int) int {
		return p.ID
	})

	// Batch fetch comment counts
	type CommentCount struct {
		PostID int `db:"post_id"`
		Count  int `db:"count"`
	}
	var commentCounts []CommentCount
	query, args, err := sqlx.In(`
		SELECT post_id, COUNT(*) as count 
		FROM comments 
		WHERE post_id IN (?)
		GROUP BY post_id`, postIDs)
	if err != nil {
		return nil, err
	}

	err = db.Select(&commentCounts, query, args...)
	if err != nil {
		return nil, err
	}

	// Create map for quick lookup
	countMap := lo.KeyBy(commentCounts, func(cc CommentCount) int {
		return cc.PostID
	})

	// Batch fetch comments with user info
	commentQuery, commentArgs, err := sqlx.In(`
		SELECT 
			c.id as id,
			c.post_id as post_id,
			c.user_id as user_id,
			c.comment as comment,
			c.created_at as created_at,
			u.id as "user.id",
			u.account_name as "user.account_name",
			u.passhash as "user.passhash",
			u.authority as "user.authority",
			u.del_flg as "user.del_flg",
			u.created_at as "user.created_at"
		FROM comments c
		JOIN users u ON c.user_id = u.id
		WHERE c.post_id IN (?)
		ORDER BY c.post_id, c.created_at DESC`, postIDs)
	if err != nil {
		return nil, err
	}

	var commentsFromDB []Comment
	err = db.Select(&commentsFromDB, commentQuery, commentArgs...)
	if err != nil {
		return nil, err
	}

	// Group comments by post_id
	commentsByPost := lo.GroupBy(commentsFromDB, func(c Comment) int {
		return c.PostID
	})

	// Build final posts
	posts := make([]Post, 0, len(results))
	for _, p := range results {
		// Set comment count
		if cc, ok := countMap[p.ID]; ok {
			p.CommentCount = cc.Count
		}

		// Get comments for this post
		if comments, ok := commentsByPost[p.ID]; ok {
			// Limit comments if needed
			if !fetchAllComments && len(comments) > 3 {
				comments = comments[:3]
			}

			// Reverse comments to show oldest first
			// lo.Reverse(comments)
			mutable.Reverse(comments)
			p.Comments = comments
		}

		// If User is already populated (from JOIN), skip the query
		if p.User.ID == 0 {
			err = db.Get(&p.User, "SELECT * FROM `users` WHERE `id` = ?", p.UserID)
			if err != nil {
				return nil, err
			}
		}

		p.CSRFToken = csrfToken
		posts = append(posts, p)
	}

	return posts, nil
}

func imageURL(p Post) string {
	ext := ""
	if p.Mime == "image/jpeg" {
		ext = ".jpg"
	} else if p.Mime == "image/png" {
		ext = ".png"
	} else if p.Mime == "image/gif" {
		ext = ".gif"
	}

	return "/image/" + strconv.Itoa(p.ID) + ext
}

func isLogin(u User) bool {
	return u.ID != 0
}

func getCSRFToken(r *http.Request) string {
	session := getSession(r)
	csrfToken, ok := session.Values["csrf_token"]
	if !ok {
		return ""
	}
	return csrfToken.(string)
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := crand.Read(k); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func getInitialize(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Clear all memcached data
	if err := memcacheClient.FlushAll(); err != nil {
		log.Printf("Failed to flush memcached: %v", err)
	}

	dbInitialize()

	// 画像抽出の完了を待つチャンネル
	done := make(chan bool)

	// 画像の抽出を非同期で実行（タイムアウト付き）
	go func() {

		if err := extractImagesToFiles(); err != nil {
			log.Printf("Failed to extract all images: %v", err)
		}
		close(done)
	}()

	time.Sleep(9*time.Second - time.Since(startTime))
	// go func() {
	// 	if _, err := http.Get("http://13.230.253.21:9000/api/group/collect"); err != nil {
	// 		slog.Error("failed to communicate with pprotein", "error", err)
	// 	}
	// }()

	w.WriteHeader(http.StatusOK)
}

func getLogin(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	if isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	templates["login"].Execute(w, struct {
		Me    User
		Flash string
	}{me, getFlash(w, r, "notice")})
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	u := tryLogin(r.FormValue("account_name"), r.FormValue("password"))

	if u != nil {
		session := getSession(r)
		session.Values["user_id"] = u.ID
		session.Values["csrf_token"] = secureRandomStr(16)
		session.Save(r, w)

		// Cache the user in memcached
		cacheKey := fmt.Sprintf("user:%d", u.ID)
		if data, err := json.Marshal(*u); err == nil {
			memcacheClient.Set(&memcache.Item{
				Key:        cacheKey,
				Value:      data,
				Expiration: 3600, // 1 hour
			})
		}

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		session := getSession(r)
		session.Values["notice"] = "アカウント名かパスワードが間違っています"
		session.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func getRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	templates["register"].Execute(w, struct {
		Me    User
		Flash string
	}{User{}, getFlash(w, r, "notice")})
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(r)
		session.Values["notice"] = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	exists := 0
	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	db.Get(&exists, "SELECT 1 FROM users WHERE `account_name` = ?", accountName)

	if exists == 1 {
		session := getSession(r)
		session.Values["notice"] = "アカウント名がすでに使われています"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	query := "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)"
	result, err := db.Exec(query, accountName, calculatePasshash(accountName, password))
	if err != nil {
		log.Print(err)
		return
	}

	session := getSession(r)
	uid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}

	session.Values["user_id"] = int(uid) // Convert to int for consistency
	session.Values["csrf_token"] = secureRandomStr(16)
	session.Save(r, w)

	// Get and cache the newly created user
	newUser := User{}
	if err := db.Get(&newUser, "SELECT * FROM `users` WHERE `id` = ?", uid); err == nil {
		cacheKey := fmt.Sprintf("user:%d", uid)
		if data, err := json.Marshal(newUser); err == nil {
			memcacheClient.Set(&memcache.Item{
				Key:        cacheKey,
				Value:      data,
				Expiration: 3600, // 1 hour
			})
		}
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	delete(session.Values, "user_id")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	results := []Post{}

	query := fmt.Sprintf(`
		SELECT 
			p.id AS id,
			p.user_id AS user_id,
			p.body AS body,
			p.mime AS mime,
			p.created_at AS created_at,
			u.id AS "user.id",
			u.account_name AS "user.account_name",
			u.passhash AS "user.passhash",
			u.authority AS "user.authority",
			u.del_flg AS "user.del_flg",
			u.created_at AS "user.created_at"
		FROM posts p
		INNER JOIN users u ON p.user_id = u.id
		WHERE u.del_flg = 0
		ORDER BY p.created_at DESC
		LIMIT %d`, postsPerPage)

	err := db.Select(&results, query)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	templates["index"].Execute(w, struct {
		Posts     []Post
		Me        User
		CSRFToken string
		Flash     string
	}{posts, me, getCSRFToken(r), getFlash(w, r, "notice")})
}

func getAccountName(w http.ResponseWriter, r *http.Request) {
	accountName := r.PathValue("accountName")
	user := User{}

	err := db.Get(&user, "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0", accountName)
	if err != nil {
		log.Print(err)
		return
	}

	if user.ID == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}

	err = db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC", user.ID)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	commentCount := 0
	err = db.Get(&commentCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = ?", user.ID)
	if err != nil {
		log.Print(err)
		return
	}

	postIDs := []int{}
	err = db.Select(&postIDs, "SELECT `id` FROM `posts` WHERE `user_id` = ?", user.ID)
	if err != nil {
		log.Print(err)
		return
	}
	postCount := len(postIDs)

	commentedCount := 0
	if postCount > 0 {
		s := []string{}
		for range postIDs {
			s = append(s, "?")
		}
		placeholder := strings.Join(s, ", ")

		// convert []int -> []interface{}
		args := make([]interface{}, len(postIDs))
		for i, v := range postIDs {
			args[i] = v
		}

		err = db.Get(&commentedCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `post_id` IN ("+placeholder+")", args...)
		if err != nil {
			log.Print(err)
			return
		}
	}

	me := getSessionUser(r)

	templates["user"].Execute(w, struct {
		Posts          []Post
		User           User
		PostCount      int
		CommentCount   int
		CommentedCount int
		Me             User
	}{posts, user, postCount, commentCount, commentedCount, me})
}

func getPosts(w http.ResponseWriter, r *http.Request) {
	m, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Print(err)
		return
	}
	maxCreatedAt := m.Get("max_created_at")
	if maxCreatedAt == "" {
		return
	}

	t, err := time.Parse(ISO8601Format, maxCreatedAt)
	if err != nil {
		log.Print(err)
		return
	}

	results := []Post{}
	query := fmt.Sprintf(`
		SELECT 
			p.id AS id,
			p.user_id AS user_id,
			p.body AS body,
			p.mime AS mime,
			p.created_at AS created_at,
			u.id AS "user.id",
			u.account_name AS "user.account_name",
			u.passhash AS "user.passhash",
			u.authority AS "user.authority",
			u.del_flg AS "user.del_flg",
			u.created_at AS "user.created_at"
		FROM posts p
		INNER JOIN users u ON p.user_id = u.id
		WHERE p.created_at <= ? 
			AND u.del_flg = 0
		ORDER BY p.created_at DESC
		LIMIT %d`, postsPerPage)

	err = db.Select(&results, query, t.Format(ISO8601Format))
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	templates["posts"].Execute(w, posts)
}

func getPostsID(w http.ResponseWriter, r *http.Request) {
	pidStr := r.PathValue("id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}
	query := `
		SELECT 
			p.id AS id,
			p.user_id AS user_id,
			p.body AS body,
			p.mime AS mime,
			p.created_at AS created_at,
			u.id AS "user.id",
			u.account_name AS "user.account_name",
			u.passhash AS "user.passhash",
			u.authority AS "user.authority",
			u.del_flg AS "user.del_flg",
			u.created_at AS "user.created_at"
		FROM posts p
		JOIN users u ON p.user_id = u.id
		WHERE p.id = ? AND u.del_flg = 0`

	err = db.Select(&results, query, pid)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), true)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	p := posts[0]

	me := getSessionUser(r)

	templates["post_id"].Execute(w, struct {
		Post Post
		Me   User
	}{p, me})
}

func postIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		session := getSession(r)
		session.Values["notice"] = "画像が必須です"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	mime := ""
	if file != nil {
		// 投稿のContent-Typeからファイルのタイプを決定する
		contentType := header.Header["Content-Type"][0]
		if strings.Contains(contentType, "jpeg") {
			mime = "image/jpeg"
		} else if strings.Contains(contentType, "png") {
			mime = "image/png"
		} else if strings.Contains(contentType, "gif") {
			mime = "image/gif"
		} else {
			session := getSession(r)
			session.Values["notice"] = "投稿できる画像形式はjpgとpngとgifだけです"
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	filedata, err := io.ReadAll(file)
	if err != nil {
		log.Print(err)
		return
	}

	if len(filedata) > UploadLimit {
		session := getSession(r)
		session.Values["notice"] = "ファイルサイズが大きすぎます"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	query := "INSERT INTO `posts` (`user_id`, `mime`, `imgdata`, `body`) VALUES (?,?,?,?)"
	result, err := db.Exec(
		query,
		me.ID,
		mime,
		filedata,
		r.FormValue("body"),
	)
	if err != nil {
		log.Print(err)
		return
	}

	pid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}

	// 画像をファイルシステムに保存
	ext := ""
	switch mime {
	case "image/jpeg":
		ext = ".jpg"
	case "image/png":
		ext = ".png"
	case "image/gif":
		ext = ".gif"
	}

	if ext != "" {
		filename := fmt.Sprintf("%d%s", pid, ext)
		imagePath := filepath.Join(ImageDir, filename)
		if err := os.WriteFile(imagePath, filedata, 0644); err != nil {
			log.Printf("Failed to save image file: %v", err)
			// エラーが発生してもリクエストは続行
		}
	}

	http.Redirect(w, r, "/posts/"+strconv.FormatInt(pid, 10), http.StatusFound)
}

func getImage(w http.ResponseWriter, r *http.Request) {
	pidStr := r.PathValue("id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	ext := r.PathValue("ext")

	// 拡張子からMIMEタイプを決定
	var expectedMime string
	switch ext {
	case "jpg":
		expectedMime = "image/jpeg"
	case "png":
		expectedMime = "image/png"
	case "gif":
		expectedMime = "image/gif"
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// nginxのtry_filesでファイルが無い場合のみここに来るので、DBから取得
	post := Post{}
	err = db.Get(&post, "SELECT * FROM `posts` WHERE `id` = ?", pid)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// MIMEタイプのチェック
	if post.Mime != expectedMime {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// 画像をファイルに保存（非同期）
	go func() {
		if err := saveImageToFile(pid, post.Mime, post.Imgdata); err != nil {
			log.Printf("Failed to save image %d: %v", pid, err)
		}
	}()

	// レスポンスを返す
	w.Header().Set("Content-Type", post.Mime)
	_, err = w.Write(post.Imgdata)
	if err != nil {
		log.Print(err)
		return
	}
}

func postComment(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	postID, err := strconv.Atoi(r.FormValue("post_id"))
	if err != nil {
		log.Print("post_idは整数のみです")
		return
	}

	query := "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)"
	_, err = db.Exec(query, postID, me.ID, r.FormValue("comment"))
	if err != nil {
		log.Print(err)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

func getAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	users := []User{}
	err := db.Select(&users, "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC")
	if err != nil {
		log.Print(err)
		return
	}

	templates["banned"].Execute(w, struct {
		Users     []User
		Me        User
		CSRFToken string
	}{users, me, getCSRFToken(r)})
}

func postAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	err := r.ParseForm()
	if err != nil {
		log.Print(err)
		return
	}

	if len(r.Form["uid[]"]) > 0 {
		// Convert string IDs to integers using lo
		userIDs := lo.FilterMap(r.Form["uid[]"], func(idStr string, _ int) (int, bool) {
			id, err := strconv.Atoi(idStr)
			if err != nil {
				log.Printf("Invalid user ID: %s", idStr)
				return 0, false
			}
			return id, true
		})

		if len(userIDs) > 0 {
			// Use IN clause to update all users at once
			query, args, err := sqlx.In("UPDATE `users` SET `del_flg` = 1 WHERE `id` IN (?)", userIDs)
			if err != nil {
				log.Print(err)
				return
			}

			_, err = db.Exec(query, args...)
			if err != nil {
				log.Print(err)
				return
			}

			// Clear cache for banned users
			for _, uid := range userIDs {
				cacheKey := fmt.Sprintf("user:%d", uid)
				memcacheClient.Delete(cacheKey)
			}
		}
	}

	http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

func main() {
	host := os.Getenv("ISUCONP_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("ISUCONP_DB_PORT")
	if port == "" {
		port = "3306"
	}
	_, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUCONP_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUCONP_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCONP_DB_PASSWORD")
	dbname := os.Getenv("ISUCONP_DB_NAME")
	if dbname == "" {
		dbname = "isuconp"
	}

	dsn := fmt.Sprintf(
		// admin prepare
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local&interpolateParams=true",
		user,
		password,
		host,
		port,
		dbname,
	)

	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}

	db.SetMaxOpenConns(64)
	db.SetMaxIdleConns(64)
	defer db.Close()

	// Initialize templates after DB connection is established
	initTemplates()

	r := chi.NewRouter()
	chiinteg.Integrate(r)

	r.Get("/initialize", getInitialize)
	r.Get("/login", getLogin)
	r.Post("/login", postLogin)
	r.Get("/register", getRegister)
	r.Post("/register", postRegister)
	r.Get("/logout", getLogout)
	r.Get("/", getIndex)
	r.Get("/posts", getPosts)
	r.Get("/posts/{id}", getPostsID)
	r.Post("/", postIndex)
	r.Get("/image/{id}.{ext}", getImage)
	r.Post("/comment", postComment)
	r.Get("/admin/banned", getAdminBanned)
	r.Post("/admin/banned", postAdminBanned)
	r.Get(`/@{accountName:[a-zA-Z]+}`, getAccountName)

	log.Fatal(http.ListenAndServe(":8080", r))
}
