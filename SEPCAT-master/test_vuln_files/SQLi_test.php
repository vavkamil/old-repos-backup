<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN">

<html>
	<head>
		<title>SQL Injection example</title>
	</head>

	<body>
		<h1>SQLi test</h1>
		<?php
			// SQL Injection
  			$id = $_POST['id'];
  			mysql_query("SELECT user FROM users WHERE id = " . $id);
		?>
	</body>
</html>