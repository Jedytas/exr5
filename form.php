<link rel="stylesheet" href="style.css">
<form action="index.php" method="POST">
  <label>
    ФИО:<br />
    <input name="fio" type="text" <?php if ($errors['fio']) {print 'class="error"';} ?> value="<?php print $values['fio']; ?>" placeholder="Фамилия, Имя, Отчество" />
  </label><br />
  <label>
    Ваш email:<br />
    <input name="email" type="email" <?php if ($errors['email']) {print 'class="error"';} ?> value="<?php print $values['email']; ?>" placeholder="Введите вашу почту" />
  </label><br />
  <label>
    Дата рождения:<br />
    <select name="year">
      <?php
      for ($i = 1922; $i <= 2024; $i++) {
        $selected = ($i == $values['year']) ? 'selected' : '';
        printf('<option value="%d" %s>%d год</option>', $i, $selected, $i);
      }
      ?>
      <?php if ($errors['year']) {print 'class="error"';} ?>
    </select>
  </label><br />
  <label>
    Пол:<br />
    <input type="radio" name="gender" <?php if($values['gender']=="male") {print("checked");}  ?>  value="male" /> Мужской
    <input type="radio" name="gender" <?php if ($errors['gender']) {print 'class="error"';} ?> <?php if($values['gender']=="female") {print("checked");} ?> value="female" /> Женский
  </label><br />
  <label>
    Выберите любимый язык программирования:<br />
    <select name="field-multiple-language[]" <?php if ($errors['field-multiple-language']) {print 'class="error"';} ?> multiple="multiple">
      <option <?php ChooseLanguage($values['field-multiple-language'], "C") ?> value="C">C</option>
      <option <?php ChooseLanguage($values['field-multiple-language'], "C++") ?> value="C++">C++</option>
      <option <?php ChooseLanguage($values['field-multiple-language'], "JavaScript") ?> value="JavaScript">JavaScript</option>
      <option <?php ChooseLanguage($values['field-multiple-language'], "PHP") ?> value="PHP">PHP</option>
      <option <?php ChooseLanguage($values['field-multiple-language'], "Python") ?> value="Python">Python</option>
      <option <?php ChooseLanguage($values['field-multiple-language'], "Java") ?> value="Java">Java</option>
      <option <?php ChooseLanguage($values['field-multiple-language'], "Haskel") ?> value="Haskel">Haskel</option>
      <option <?php ChooseLanguage($values['field-multiple-language'], "Clojure") ?> value="Clojure">Clojure</option>
      <option <?php ChooseLanguage($values['field-multiple-language'], "Prolog") ?> value="Prolog">Prolog</option>
      <option <?php ChooseLanguage($values['field-multiple-language'], "Scala") ?> value="Scala">Scala</option>
    </select>
  </label><br />
  <label>
    Расскажите о себе!<br />
    <textarea name="biography" <?php if ($errors['biography']) {print 'class="error"';} ?>><?php print htmlspecialchars($values['biography']); ?></textarea>
  </label><br />

  <label>
    <input type="checkbox" name="checkcontract" <?php if ($errors['checkcontract']) {print 'class="error"';} ?> <?php if($values['checkcontract'] == 1) print "checked" ?> /> С контрактом ознакомлен(а)
  </label><br />
  <input type="hidden" name="csrf_form_token" value="<?=$val?>">
  <input type="submit" value="ok" />
</form>
<?php 
if (!empty($messages)) {
  print('<div id="messages">');
  foreach ($messages as $message) {
    print($message);
  }
  print('</div>');
}

function ChooseLanguage($langsval, $value){
  $langArray = str_getcsv($langsval, ',');
  for($i = 0; $i < count($langArray); $i++){
    if($langArray[$i] == $value)
    print "selected";
  }
}
  ?>