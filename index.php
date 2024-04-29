<?php
header('Content-Type: text/html; charset=UTF-8');


if ($_SERVER['REQUEST_METHOD'] == 'GET') {

  $messages = array();

  if (!empty($_COOKIE['save'])) {
    setcookie('save', '', 100000);
    setcookie('login', '', 100000);
    setcookie('pass', '', 100000);
    $messages[] = 'Спасибо, результаты сохранены.';
    if (!empty($_COOKIE['pass'])) {
      $messages[] = sprintf('Вы можете <a href="login.php">войти</a> с логином <strong>%s</strong>
        и паролем <strong>%s</strong> для изменения данных.',
        strip_tags($_COOKIE['login']),
        strip_tags($_COOKIE['pass']));
    }
  }
$errors = array();
$errors['fio'] = !empty($_COOKIE['fio_error']);
$errors['email'] = !empty($_COOKIE['email_error']);
$errors['year'] = !empty($_COOKIE['year_error']);
$errors['gender'] = !empty($_COOKIE['gender_error']);
$errors['field-multiple-language'] = !empty($_COOKIE['langs_error']);
$errors['biography'] = !empty($_COOKIE['biography_error']);
$errors['checkcontract'] = !empty($_COOKIE['checkcontract_error']);


if ($errors['fio']) {

  setcookie('fio_error', '', 100000);
  setcookie('fio_value', '', 100000);

  $messages[] = '<div class="error">Заполните имя.</div>';
}
if ($errors['email']) {
  setcookie('email_error', '', 100000);
  setcookie('email_value', '', 100000);
  $messages[] = '<div class="error">Заполните email.</div>';
}
if ($errors['year']) {
  setcookie('year_error', '', 100000);
  setcookie('year_value', '', 100000);
  $messages[] = '<div class="error">Заполните год.</div>';
}
if ($errors['gender']) {
  setcookie('gender_error', '', 100000);
  setcookie('gender_value', '', 100000);
  $messages[] = '<div class="error">Выберете один из вариантов.</div>';
}
if ($errors['field-multiple-language']) {
  setcookie('langs_error', '', 100000);
  setcookie('langs_value', '', 100000);
  $messages[] = '<div class="error">Выберете хотя бы один язык.</div>';
}
if ($errors['biography']) {
  setcookie('biography_error', '', 100000);
  setcookie('biography_value', '', 100000);
  $messages[] = '<div class="error">Заполните биографию.</div>';
}
if ($errors['checkcontract']) {
  setcookie('checkcontract_error', '', 100000);
  setcookie('checkcontract_value', '', 100000);
  $messages[] = '<div class="error">Согласие обязательно.</div>';
}


$values = array();
$values['fio'] = empty($_COOKIE['fio_value']) ? '' : $_COOKIE['fio_value'];
$values['email'] = empty($_COOKIE['email_value']) ? '' : $_COOKIE['email_value'];
$values['year'] = empty($_COOKIE['year_value']) ? '' : $_COOKIE['year_value'];
$values['gender'] = empty($_COOKIE['gender_value']) ? '' : $_COOKIE['gender_value'];
$values['field-multiple-language'] = empty($_COOKIE['langs_value']) ? '' : $_COOKIE['langs_value'];
$values['biography'] = empty($_COOKIE['biography_value']) ? '' : $_COOKIE['biography_value'];
$values['checkcontract'] = empty($_COOKIE['checkcontract_value']) ? '' : $_COOKIE['checkcontract_value'];


if (!empty($_COOKIE[session_name()]) &&
session_start() && !empty($_SESSION['login'])) {
$userLogin = $_SESSION['login'];

include('config.php');

$db = new PDO('mysql:host=localhost;dbname=u67278', $db_user, $db_password,
[PDO::ATTR_PERSISTENT => true, PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]); 

try {
  $formId;
  $sth = $db->prepare('SELECT FormId FROM Users WHERE Login = :login');
  $sth->execute(['login' => $userLogin]);

  while ($row = $sth->fetch()) {
    $formId = $row['FormId'];
  }
  $sth = $db->prepare('SELECT fio, year, email, gender, biography, checkcontract FROM Applications WHERE id = :id');
    $sth->execute(['id' => $formId]);
    while ($row = $sth->fetch()) {
      $values['fio'] = $row['fio'];
      $values['year'] = $row['year'];
      $values['email'] = $row['email'];
      $values['gender'] = $row['gender'];
      $values['biography'] = $row['biography'];
      $values['checkcontract'] = $row['checkcontract'];
    }

    $sth = $db->prepare('SELECT language_id FROM application_language WHERE application_id = :id');
    $sth->execute(['id' => $formId]);
    $j = 0;
    $langsval = [];
    $row = $sth->fetchAll();
    for($i = 0; $i < count($row); $i++) {
      $sth = $db->prepare('SELECT name FROM programming_language WHERE id = :id');
      $sth->execute(['id' => ($row[$i])['language_id']]);
      while ($langrow = $sth->fetch()) {
        $langsval[$j++] = $langrow['name'];
      }
    }
    $langsCV = '';
    for($i = 0; $i < count($langsval); $i++)
    {
      $langsCV .= $langsval[$i] . ",";
    }
    $values['field-multiple-language'] = $langsCV;
    
}
catch(PDOException $e){
  print('Error : ' . $e->getMessage());
  exit();
}

setcookie('fio_value', $values['fio'], time() + 30 * 24 * 60 * 60);
setcookie('email_value', $values['email'], time() + 30 * 24 * 60 * 60);
setcookie('year_value', $values['year'], time() + 30 * 24 * 60 * 60);
setcookie('gender_value', $values['gender'], time() + 30 * 24 * 60 * 60);
setcookie('langs_value', $values['field-multiple-language'], time() + 30 * 24 * 60 * 60);
setcookie('biography_value', $values['biography'], time() + 30 * 24 * 60 * 60);
setcookie('checkcontract_value', $values['checkcontract'], time() + 30 * 24 * 60 * 60);

  printf('Вход с логином %s', $_SESSION['login']);
}
$val = RandString();
setcookie('csrf_form_token', $val, time() + 30 * 24 * 60 * 60);

include('form.php');
}

else
{

  if($_POST['csrf_form_token'] != $_COOKIE['csrf_form_token'])
  {
    print("csrf attack");
    exit();
  }

  $errors = FALSE;
  $fioval = $_POST['fio'];
  $emailval = $_POST['email'];
  $yearval = $_POST['year'];
  $genderval = $_POST['gender'];
  $checkval = !empty($_POST['checkcontract']);
  $bioval = $_POST['biography'];
  $langsval = !empty($_POST['field-multiple-language'])?$_POST['field-multiple-language']:null;
  
  $langsCV = '';
  if($langsval != null && !empty($langsval))
  {
    for($i = 0; $i < count($langsval); $i++)
    {
      $langsCV .= $langsval[$i] . ",";
    }
  }
  if (!preg_match("/^[a-zA-Zа-яА-Я\s]+$/u", $fioval) || empty($fioval)) {
    setcookie('fio_error', '1', time() + 24 * 60 * 60);
    $errors = TRUE;
  }
  setcookie('fio_value', $fioval, time() + 30 * 24 * 60 * 60);
  if (empty($yearval) || !is_numeric($yearval) || !preg_match('/^\d+$/', $yearval)){
    setcookie('year_error', '1', time() + 24 * 60 * 60);
    $errors = TRUE;
  }
  setcookie('year_value', $yearval, time() + 30 * 24 * 60 * 60);
  if (empty($emailval) || !filter_var($emailval, FILTER_VALIDATE_EMAIL)){
    setcookie('email_error', '1', time() + 24 * 60 * 60);
    $errors = TRUE;
  }
  setcookie('email_value', $emailval, time() + 30 * 24 * 60 * 60);
  if (empty($genderval) || ($genderval != 'male' && $genderval != 'female')) {
    setcookie('gender_error', '1', time() + 24 * 60 * 60);
    $errors = TRUE;
  }
  setcookie('gender_value', $genderval, time() + 30 * 24 * 60 * 60);
  if (empty($langsval)) {
    setcookie('langs_error', '1', time() + 24 * 60 * 60);
    $errors = TRUE;
  }
  else
  {
    setcookie('langs_value', $langsCV, time() + 30 * 24 * 60 * 60);
  }
  if (empty($bioval) || strlen($bioval) > 150) {
    setcookie('biography_error', '1', time() + 24 * 60 * 60);
    $errors = TRUE;
  }
  setcookie('biography_value', $bioval, time() + 30 * 24 * 60 * 60);
  if (empty($checkval)) {
    setcookie('checkcontract_error', '1', time() + 24 * 60 * 60);
    $errors = TRUE;
  }
  setcookie('checkcontract_value', $checkval, time() + 30 * 24 * 60 * 60);


  if ($errors) {
    header('Location: index.php');
    exit();
  }
  else
  {
    setcookie('fio_error', '', 100000);
    setcookie('email_error', '', 100000);
    setcookie('year_error', '', 100000);
    setcookie('langs_error', '', 100000);
    setcookie('gender_error', '', 100000);
    setcookie('biography_error', '', 100000);
    setcookie('checkcontract_error', '', 100000);
  }
  print('Валидация прошла успешно!');

  include('config.php');

  $db = new PDO('mysql:host=localhost;dbname=u67278', $db_user, $db_password,
  [PDO::ATTR_PERSISTENT => true, PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]); 
if (!empty($_COOKIE[session_name()]) &&
      session_start() && !empty($_SESSION['login'])) {
    $userLogin = $_SESSION['login'];
    $formId = GetLoginID($db, $userLogin);

    $stmt = $db->prepare("UPDATE Applications SET fio = :fio, year = :year, email = :email,  gender = :gender, biography = :biography, checkcontract = :checkcontract WHERE id = :id");
    $stmt -> execute(['fio'=>$fioval, 'email'=>$emailval,'year'=>$yearval,'gender'=>$genderval,'biography'=>$bioval, 'checkcontract'=>$checkval, 'id' => $formId]);

    $stmt = $db->prepare("DELETE FROM application_language WHERE application_id = :formId");
    $stmt -> execute(['formId'=>$formId]);
    $langId;
    for($i = 0; $i < count($langsval); $i++)
    {
        $langId = null;
        $sth = $db->prepare('SELECT id FROM programming_language WHERE name = :langName');
        $sth->execute(['langName' => $langsval[$i]]);
        while ($row = $sth->fetch()) {
          $langId = $row['Id'];
        }
        if($langId == null)
        {
          $stmt = $db->prepare("INSERT INTO programming_language (name) VALUES (:languageNameDB)");
          $stmt -> execute(['languageNameDB'=>$langsval[$i]]);

          $langId = $db->lastInsertId();
        }

        $stmt = $db->prepare("INSERT INTO application_language (application_id, language_id) VALUES (:formId, :languageIdDB)");
        $stmt -> execute(['formId'=>$formId, 'languageIdDB'=>$langId]);
    }
  }
  else {
    $login = RandString();
    $pass = RandString();
    $shapass = sha1($pass);
    setcookie('login', $login);
    setcookie('pass', $pass);
  try {
    $stmt = $db->prepare("INSERT INTO Applications (fio, year, email, gender, biography, checkcontract) VALUES (?, ?, ?, ?, ?, ?)");
    $checkContractValue = $_POST['checkcontract'] === 'on' ? 1 : 0;
    $stmt->execute([$_POST['fio'], $_POST['year'], $_POST['email'], $_POST['gender'], $_POST['biography'], $checkContractValue]);

        $lastInsertId = $db->lastInsertId();
        $FormId = $db->lastInsertId();

        if (!empty($_POST['field-multiple-language'])) {
          $languages = $_POST['field-multiple-language'];
          foreach ($languages as $language) {
              $stmt = $db->prepare("SELECT id FROM programming_language WHERE name = ?");
              $stmt->execute([$language]);
              $row = $stmt->fetch(PDO::FETCH_ASSOC);
      
              if (!$row) {
                  $stmt = $db->prepare("INSERT INTO programming_language (name) VALUES (?)");
                  $stmt->execute([$language]);
                  $languageId = $db->lastInsertId();
              } else {
                  $languageId = $row['id'];
              }
      
              $stmt = $db->prepare("INSERT INTO application_language (application_id, language_id) VALUES (?, ?)");
              $stmt->execute([$lastInsertId, $languageId]);
          }
      }
      $stmt = $db->prepare("INSERT INTO Users (FormId, Login, Password) VALUES (:formId, :login, :pass)");
        $stmt -> execute(['formId'=>$FormId, 'login'=>$login,'pass'=>$shapass]);
      print('Данные успешно сохранены!');
  }
  catch(PDOException $e){
    print('Error : ' . $e->getMessage());
    exit();
  }
}
setcookie('save', '1');
header('Location: index.php');
}


function GetLoginID($db, $login)
{
    $formId = null;
    $sth = $db->prepare('SELECT FormId FROM Users WHERE Login = :login');
    $sth->execute(['login' => $login]);
    while ($row = $sth->fetch()) {
      $formId = $row['FormId'];
    }
  return $formId;
}
function RandString($length = 10) {
  $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  $str = '';
  for ($i = 0; $i < $length; $i++) {
      $str .= $characters[rand(0, strlen($characters) - 1)];
  }
  return $str;
}
