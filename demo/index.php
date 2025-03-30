<?php
/**
 * index.php
 *
 * PHP version 7
 *
 * @category  WWPass_Demo
 * @package   WWPass_PHP_Demo
 * @author    Mikhail Vysogorets <m.vysogorets@wwpass.com>
 * @copyright 2020 WWPass
 * @license   http://opensource.org/licenses/mit-license.php The MIT License
 */

session_start();

if (!isset($_SESSION['PUID'])) {
    header("Location: logout.php");
    exit();
}

?>

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WWPass demo</title>
  </head>
  <body  bgcolor='#E6E6FA'>
    <h1>You are now signed in </h1>
    <p>
      Your puid is <?php echo $_SESSION['PUID'] ?>
    </p>
    <div>
      <a href = logout.php> Logout </a>
    </div>
  </body>
</html>
