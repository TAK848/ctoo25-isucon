package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func dbInitialize() {
	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		"UPDATE users SET del_flg = 0",
		"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
		// EXPLAIN SELECT * FROM `comments` WHERE `post_id` = 1 ORDER BY `created_at` DESC LIMIT 100; 狙いのindex追加
		// "CREATE INDEX IF NOT EXISTS `idx_post_id_created_at` ON `comments` (`post_id`, `created_at` DESC)",
		// ALTER TABLE `posts` ADD INDEX `idx_posts_created_at` (`created_at` DESC);
		// ALTER TABLE `comments` ADD INDEX `idx_comments_user_id` (`user_id` DESC);
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}

	// // 既存の画像をファイルシステムに書き出す
	// if err := extractImagesToFiles(); err != nil {
	// 	log.Printf("Failed to extract images: %v", err)
	// }
}

// 画像をファイルシステムに書き出す
func extractImagesToFiles() error {
	// 画像ディレクトリが存在しない場合は作成
	if err := os.MkdirAll(ImageDir, 0755); err != nil {
		return fmt.Errorf("failed to create image directory: %w", err)
	}

	// ID > 10000 の画像ファイルのみ削除
	files, err := filepath.Glob(filepath.Join(ImageDir, "*"))
	if err != nil {
		log.Printf("Failed to list image files: %v", err)
	} else {
		for _, file := range files {
			base := filepath.Base(file)
			// ファイル名から拡張子を除いたIDを取得
			var id int
			if _, err := fmt.Sscanf(base, "%d.", &id); err == nil && id > 10000 {
				if err := os.Remove(file); err != nil {
					log.Printf("Failed to remove image file %s: %v", file, err)
				}
			}
		}
	}
	return nil

	// ID <= 10000 の新規画像を取得して保存
	rows, err := db.Query("SELECT id, mime, imgdata FROM posts WHERE imgdata IS NOT NULL AND id <= 10000")
	if err != nil {
		return fmt.Errorf("failed to query images: %w", err)
	}
	defer rows.Close()

	var count int
	for rows.Next() {
		var id int
		var mime string
		var imgdata []byte

		if err := rows.Scan(&id, &mime, &imgdata); err != nil {
			log.Printf("Failed to scan image row: %v", err)
			continue
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
			log.Printf("Unknown mime type for post %d: %s", id, mime)
			continue
		}

		// ファイルパスを生成
		filename := fmt.Sprintf("%d%s", id, ext)
		filepath := filepath.Join(ImageDir, filename)

		// ファイルに書き込み
		if err := os.WriteFile(filepath, imgdata, 0644); err != nil {
			log.Printf("Failed to write image file %s: %v", filepath, err)
			continue
		}

		count++
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating images: %w", err)
	}

	log.Printf("Extracted %d images to %s", count, ImageDir)
	return nil
}
