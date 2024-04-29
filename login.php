<?php

/**
 * Файл login.php для не авторизованного пользователя выводит форму логина.
 * При отправке формы проверяет логин/пароль и создает сессию,
 * записывает в нее логин и id пользователя.
 * После авторизации пользователь перенаправляется на главную страницу
 * для изменения ранее введенных данных.
 **/

header('Content-Type: text/html; charset=UTF-8');


$session_started = false;
if (session_start() && !empty($_COOKIE[session_name()])) {
  $session_started = true;
  if (!empty($_SESSION['login'])) {

    include("logoutPage.php");
    if (isset($_POST['Logout']))
    {
      session_destroy();
      header('Location: ./');
    }
    
    exit();
  }
}

if ($_SERVER['REQUEST_METHOD'] == 'GET') {
  $val = RandString();
  setcookie('csrf_token', $val, time() + 30 * 24 * 60 * 60);
  include("loginPage.php");
}
else {
  
  if($_POST['csrf_token'] != $_COOKIE['csrf_token'])
  {
    print("csrf_attack");
    exit();
  }
  
  include('config.php');

  $db = new PDO('mysql:host=localhost;dbname=u67278', $db_user, $db_password,
  [PDO::ATTR_PERSISTENT => true, PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]); 

  $passDB = null;
  $login = htmlspecialchars($_POST['login'], ENT_QUOTES, 'UTF-8');
  $pass = htmlspecialchars($_POST['pass'], ENT_QUOTES, 'UTF-8');
  $shapass = sha1($pass);
  try{
    $sth = $db->prepare('SELECT Password FROM Users WHERE Login = :login');
    $sth->execute(['login' => $login]);
    
    while ($row = $sth->fetch()) {
      $passDB = $row['Password'];
    }
  }
  catch(PDOException $e){
    print('Error : ' . $e->getMessage());
    exit();
  }
  

  if($passDB == "" || $passDB != $shapass)
  {
    print("No such login or incorrect password");
  }
  else{
    if (!$session_started) {
      session_start();
    }
    $_SESSION['login'] = $_POST['login'];
    header('Location: ./');
  }
  
}

function RandString($length = 10) {
  $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  $str = '';
  for ($i = 0; $i < $length; $i++) {
      $str .= $characters[rand(0, strlen($characters) - 1)];
  }
  return $str;
}
