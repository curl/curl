<?php
// Allocate a new cURL handle
$ch = curl_init("http://www.designmultimedia.com/intro.jpg");
if (! $ch) {
	die( "Cannot allocate a new PHP-CURL handle" );
}

// We'll be returning this transfer, and the data is binary
// so we don't want to NULL terminate
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_BINARYTRANSFER, 1);

// Grab the jpg and save the contents in the $data variable
$data = curl_exec($ch);

// close the connection
curl_close($ch);

// Set the header to type image/jpeg, since that's what we're
// displaying
header("Content-type: image/jpeg");

// Output the image
print( $data );
?>
