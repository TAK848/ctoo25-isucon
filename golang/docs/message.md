# CTO 協会 合同 ISUCON 研修 当日マニュアル

## 当日の流れ

- 10:00 競技開始
- 18:00 競技終了

## ポータルサイト

[https://master.d3nv83zcy273s8.amplifyapp.com/](https://master.d3nv83zcy273s8.amplifyapp.com/)

上記リンクを開いて、配布されたusernameでログインしてください。
計測ツールで測定したスコアはこのポータルに送られ、集計結果を見ることができます。

## Getting Started

はじめに以下の操作を行い、問題なく動くかを確認して下さい。

### 2. 起動した EC2 インスタンスに `ubuntu` ユーザで SSH ログインし、鍵の変更をする

ログイン例:

```
ssh -i <配布した鍵ファイル> ubuntu@xx.xx.xx.xx
```

これで EC2 インスタンスにログインできます。この状態では、他のチームの人も配布した鍵でログインできてしまうので、独自の鍵に変更します。

鍵の変更手順例：

```
### キーペアの生成

ubuntu:~$ ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/home/ubuntu/.ssh/id_rsa):
Created directory '/home/ubuntu/.ssh'.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/ubuntu/.ssh/id_rsa
Your public key has been saved in /home/ubuntu/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:ejdWFdpyYZlaQ0bgMLbtgul0sD7K4jxUPDRA6cFsl8Q test1@ip-172-31-32-81
The key's randomart image is:
+---[RSA 3072]----+
|   +o=..  + .+Bo |
|    * E  . * ==o |
|   o = .. . =o+. |
|    . +  = ..+   |
|     . .S o o    |
|    .  = . o     |
|   .  . = +      |
|   .o. o + .     |
|   .ooo          |
+----[SHA256]-----+

### 秘密鍵をローカルに持ってくる

ubuntu:~$ cat ~/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
=== 途中略 ===
I8FRb+ClG4YLtts/ucucj7qoc9ctLGgnzLycKmZ8z2BoXyNhGnAin/K0VtPq/ssbMyCo66
sFc3HdTxmaBm0AAAAVdGVzdDFAaXAtMTcyLTMxLTMyLTgxAQIDBAUG
-----END OPENSSH PRIVATE KEY-----


上記をコピーして、ローカルファイルに保存する。(例： ctoa_isucon.pem とか)
ローカルで、鍵のパーミッションを変える

local:~$ chmod 600 ctoa_isucon.pem

### 公開鍵の反映

ubuntu:~$ cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys

### ローカルから新しい鍵でログインできるか確認

local:~$ ssh -i ctoa_isucon.pem ubuntu@xxx.xxx.xxx.xxx
(Windowsの方は、SSHクライアントで同様のことを行う)

### もともと配られていた公開鍵を消す

ubuntu:~$ cat ~/.ssh/id_rsa.pub > ~/.ssh/authorized_keys

### もう一度、ローカルから新しい鍵でログインできるか確認

local:~$ ssh -i ctoa_isucon.pem ubuntu@xxx.xxx.xxx.xxx
(Windowsの方は、SSHクライアントで同様のことを行う)
```

同様の手順で、`isucon`ユーザーでログインできるようにすると、この後の作業が楽になりますのでおすすめです。
ログイン後、`isucon`ユーザーに切り替えるには以下のコマンドを実行してください。

```
sudo su - isucon
```

### 3. アプリケーションの動作を確認

EC2インスタンスのパブリックIPアドレスにブラウザでアクセスし、動作を確認してください。以下の画面が表示されるはずです。

例として、「アカウント名」は `mary`、 「パスワード」は `marymary` を入力することでログインが行えます。

ブラウザでアクセスできない場合、Discordで主催者に確認してください。

### 4. 負荷走行を実行

EC2上で、以下のコマンドを実行します。

```
curl https://xnvvb925bl.execute-api.ap-northeast-1.amazonaws.com/
```

この操作後、ポータルにて、あなたのチームのスコアが反映されているか確認して下さい。負荷走行を実行すると、あなたのアプリケーションに対して自動的にリクエストが送信され、その結果がポータルサイトのスコアに反映されます。スコアの反映には数分かかる場合があります。

### ディレクトリ構成

参考実装のアプリケーションコードおよび、スコア計測用プログラムは `/home/isucon` ディレクトリ以下にあります。

```
/home/isucon/
  ├ env.sh       # アプリケーション用の環境変数
  └ private_isu/
     └ webapp/    # 各言語の参考実装
```

### 参考実装の言語切り替え方法

初期状態ではRubyによる参考実装が起動しています。これをベースに最適化を進めるか、必要に応じてPHP、Go、またはPythonの参考実装に切り替えることができます。一度に起動できるアプリケーション言語は1つだけです。基本的な切り替え手順は、現在動作しているRubyのサービス(`isu-ruby`)を停止・無効化し、その後、目的の言語のサービスを起動・有効化します。PHPへ切り替える場合、またはPHPからRubyへ戻す場合は、Nginxの設定変更も伴います。

80番ポートでアクセスできるので、ブラウザから動作確認をすることができます。

プログラムの詳しい起動方法は、 /etc/systemd/system/isu-ruby.service を参照してください。

エラーなどの出力については、

```bash
$ sudo journalctl -f -u isu-ruby
```

などで見ることができます。

また、unicornの再起動は、

```bash
$ sudo systemctl restart isu-ruby
```

などですることができます。

#### PHP (php8.3-fpm) への切り替え方

Ruby実装からPHP実装に切り替えるには、以下の操作を行います。まず、Rubyサービスを停止・無効化します:

```bash
$ sudo systemctl stop isu-ruby
$ sudo systemctl disable isu-ruby
```

```bash
$ sudo rm /etc/nginx/sites-enabled/isucon.conf
$ sudo ln -s /etc/nginx/sites-available/isucon-php.conf /etc/nginx/sites-enabled/
$ sudo systemctl reload nginx
```

```bash
$ sudo systemctl start php8.3-fpm
$ sudo systemctl enable php8.3-fpm
```

php-fpmの設定については、`/etc/php/8.3/fpm/` 以下にあります。

エラーなどの出力については、

```bash
$ sudo journalctl -f -u php8.3-fpm
$ sudo tail -f /var/log/nginx/error.log
```

などで見ることができます。

#### Go (isu-go) への切り替え方

Ruby実装からGo実装に切り替えるには、以下の操作を行います。まず、Rubyサービスを停止・無効化します:

```bash
$ sudo systemctl stop isu-ruby
$ sudo systemctl disable isu-ruby
```

```bash
$ sudo systemctl start isu-go
$ sudo systemctl enable isu-go
```

プログラムの詳しい起動方法は、 /etc/systemd/system/isu-go.service を参照してください。

エラーなどの出力については、

```bash
$ sudo journalctl -f -u isu-go
```

などで見ることができます。

#### Python (isu-python) への切り替え方

Ruby実装からPython実装に切り替えるには、以下の操作を行います。まず、Rubyサービスを停止・無効化します:

```bash
$ sudo systemctl stop isu-ruby
$ sudo systemctl disable isu-ruby
```

```bash
# Python 用 systemd ユニットを有効化・起動
$ sudo systemctl start isu-python
$ sudo systemctl enable isu-python
```

プログラムの詳しい起動方法は、`/etc/systemd/system/isu-python.service`を参照してください。

```bash
# リアルタイムでログを追う
$ sudo journalctl -f -u isu-python
```

### MySQL

3306番ポートでMySQLが起動しています。初期状態では以下のユーザが設定されています。

  * ユーザ名: `isuconp`, パスワード: `isuconp`

### memcached

11211番ポートでmemcachedが起動しています。


## ルール詳細

[社内ISUCON 当日レギュレーション](/public_manual.md)

本マニュアルは、競技環境の技術的な詳細と操作手順を提供します。当日レギュレーション (`public_manual.md`) には競技全体のルールが記載されています。原則として、競技ルールについては `public_manual.md` を、技術的な操作や環境については本マニュアルを参照してください。

### スコアについて

基本スコアは以下のルールで算出されます。

```
成功レスポンス数(GET) x 1 + 成功レスポンス数(POST) x 2 + 成功レスポンス数(画像投稿) x 5 - (サーバエラー(error)レスポンス数 x 10 + リクエスト失敗(exception)数 x 20 + 遅延POSTレスポンス数 x 100)
```

ただし、基本スコアと計測ツールの出すスコアが異なっている場合は、計測ツールの出すスコアが優先されます。

#### 減点対象

以下の事項に抵触すると減点対象となります。

  * 存在するべきファイルへのアクセスが失敗する
  * リクエスト失敗（通信エラー等）が発生する
  * サーバエラー(Status 5xx)・クライアントエラー(Status 4xx)をアプリケーションが返す
  * 他、計測ツールのチェッカが検出したケース

#### 注意事項

  * リダイレクトはリダイレクト先が正しいレスポンスを返せた場合に、1回レスポンスが成功したと判断します
  * POSTの失敗は大幅な減点対象です

### 制約事項

以下の事項に抵触すると点数が無効となります。

  * GET /initialize へのレスポンスが10秒以内に終わらない
  * 存在するべきDOM要素がレスポンスHTMLに存在しない

## 当日サポートについて

にてサポートを行います。また、現地にメンターが常駐しますのでアプリケーションチューニングに関する相談も可能です。