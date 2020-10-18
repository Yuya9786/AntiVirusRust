rule UPX {
	strings:
		$hex_string = { 55 50 58 21 }
	condition:
		$hex_string
}
