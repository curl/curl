#
# The PHP curl module supports the received page to be returned in a variable
# if told.
#
$ch = curl_init();

curl_setopt($ch, CURLOPT_URL,"http://www.myurl.com/");
curl_setopt($ch, CURLOPT_RETURNTRANSFER,1);
$result=curl_exec ($ch);
curl_close ($ch);
