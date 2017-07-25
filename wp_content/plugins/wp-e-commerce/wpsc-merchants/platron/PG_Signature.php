<?php
class PG_Signature {

	/**
	 * Get script name from URL (for use as parameter in self::make, self::check, etc.)
	 *
	 * @param string $url
	 * @return string
	 */
	public static function getScriptNameFromUrl ( $url )
	{
		$path = parse_url($url, PHP_URL_PATH);
		$len  = strlen($path);
		if ( $len == 0  ||  '/' == $path{$len-1} ) {
			return "";
		}
		return basename($path);
	}
	
	/**
	 * Get name of currently executed script (need to check signature of incoming message using self::check)
	 *
	 * @return string
	 */
	public static function getOurScriptName ()
	{
		return self::getScriptNameFromUrl( $_SERVER['PHP_SELF'] );
	}

	/**
	 * Creates a signature
	 *
	 * @param array $arrParams  associative array of parameters for the signature
	 * @param string $strSecretKey
	 * @return string
	 */
	public static function make ( $strScriptName, $arrParams, $strSecretKey )
	{
		return md5( self::makeSigStr($strScriptName, $arrParams, $strSecretKey) );
	}

	/**
	 * Verifies the signature
	 *
	 * @param string $signature
	 * @param array $arrParams  associative array of parameters for the signature
	 * @param string $strSecretKey
	 * @return bool
	 */
	public static function check ( $signature, $strScriptName, $arrParams, $strSecretKey )
	{
		return (string)$signature === self::make($strScriptName, $arrParams, $strSecretKey);
	}


	/**
	 * Returns a string, a hash of which coincide with the result of the make() method.
	 * WARNING: This method can be used only for debugging purposes!
	 *
	 * @param array $arrParams  associative array of parameters for the signature
	 * @param string $strSecretKey
	 * @return string
	 */
	static function debug_only_SigStr ( $strScriptName, $arrParams, $strSecretKey ) {
		return self::makeSigStr($strScriptName, $arrParams, $strSecretKey);
	}

	private static function makeSigStr ( $strScriptName, $arrParams, $strSecretKey ) {
		unset($arrParams['pg_sig']);
		ksort($arrParams);
		return $strScriptName .';' . self::arJoin($arrParams) . ';' . $strSecretKey;
	}

	private static function arJoin ($in) {
		return substr_replace(self::arJoinProcess($in, ''), '', -1);
	}

	private static function arJoinProcess ($in, $str) {
		if (is_array($in)) {
			ksort($in);
			$s = '';
			foreach($in as $v) {
				$s .= self::arJoinProcess($v, $str);
			}
			return $s;
		} else {
			return $str . $in . ';';
		}
	}
	
	private static function makeFlatParamsArray ( $arrParams, $parent_name = '' )
	{
		$arrFlatParams = array();
		$i = 0;
		foreach ( $arrParams as $key => $val ) {
			
			$i++;
			if ( 'pg_sig' == $key )
				continue;
				
			/**
			 * Имя делаем вида tag001subtag001
			 * Чтобы можно было потом нормально отсортировать и вложенные узлы не запутались при сортировке
			 */
			$name = $parent_name . $key . sprintf('%03d', $i);

			if (is_array($val) ) {
				$arrFlatParams = array_merge($arrFlatParams, self::makeFlatParamsArray($val, $name));
				continue;
			}

			$arrFlatParams += array($name => (string)$val);
		}

		return $arrFlatParams;
	}

	/********************** singing XML ***********************/

	/**
	 * make the signature for XML
	 *
	 * @param string|SimpleXMLElement $xml
	 * @param string $strSecretKey
	 * @return string
	 */
	public static function makeXML ( $strScriptName, $xml, $strSecretKey )
	{
		$arrFlatParams = self::makeFlatParamsXML($xml);
		return self::make($strScriptName, $arrFlatParams, $strSecretKey);
	}

	/**
	 * Verifies the signature of XML
	 *
	 * @param string|SimpleXMLElement $xml
	 * @param string $strSecretKey
	 * @return bool
	 */
	public static function checkXML ( $strScriptName, $xml, $strSecretKey )
	{
		if ( ! $xml instanceof SimpleXMLElement ) {
			$xml = new SimpleXMLElement($xml);
		}
		$arrFlatParams = self::makeFlatParamsXML($xml);
		return self::check((string)$xml->pg_sig, $strScriptName, $arrFlatParams, $strSecretKey);
	}

	/**
	 * Returns a string, a hash of which coincide with the result of the makeXML() method.
	 * WARNING: This method can be used only for debugging purposes!
	 *
	 * @param string|SimpleXMLElement $xml
	 * @param string $strSecretKey
	 * @return string
	 */
	public static function debug_only_SigStrXML ( $strScriptName, $xml, $strSecretKey )
	{
		$arrFlatParams = self::makeFlatParamsXML($xml);
		return self::makeSigStr($strScriptName, $arrFlatParams, $strSecretKey);
	}

	/**
	 * Returns flat array of XML params
	 *
	 * @param (string|SimpleXMLElement) $xml
	 * @return array
	 */
	private static function makeFlatParamsXML ( $xml, $parent_name = '' )
	{
		if ( ! $xml instanceof SimpleXMLElement ) {
			$xml = new SimpleXMLElement($xml);
		}

		$arrParams = array();
		$i = 0;
		foreach ( $xml->children() as $tag ) {
			
			$i++;
			if ( 'pg_sig' == $tag->getName() )
				continue;
				
			/**
			 * Имя делаем вида tag001subtag001
			 * Чтобы можно было потом нормально отсортировать и вложенные узлы не запутались при сортировке
			 */
			$name = $parent_name . $tag->getName().sprintf('%03d', $i);

			if ( $tag->children()->count() > 0 ) {
				$arrParams = array_merge($arrParams, self::makeFlatParamsXML($tag, $name));
				continue;
			}

			$arrParams += array($name => (string)$tag);
		}

		return $arrParams;
	}
}


class OfdReceiptRequest
{
	const SCRIPT_NAME = 'receipt.php';

	public $merchantId;
	public $operationType = 'payment';
	public $paymentId;
	public $items = array();

	private $params = array();

	public function __construct($merchantId, $paymentId)
	{
		$this->merchantId = $merchantId;
		$this->paymentId = $paymentId;
	}

	public function sign($secretKey)
	{
		$params = $this->toArray();
		$params['pg_salt'] = 'salt';
		$params['pg_sig'] = PG_Signature::make(self::SCRIPT_NAME, $params, $secretKey);

		$this->params = $params;
	}

	public function toArray()
	{
		$result = array();

		$result['pg_merchant_id'] = $this->merchantId;
		$result['pg_operation_type'] = $this->operationType;
		$result['pg_payment_id'] = $this->paymentId;

		foreach ($this->items as $item) {
			$result['pg_items'][] = $item->toArray();
		}

		return $result;
	}

	public function requestArray()
	{
		return $this->params;
	}

	public function makeXml()
	{
		//var_dump($this->params);
		$xmlElement = new SimpleXMLElement('<?xml version="1.0" encoding="UTF-8"?><request></request>');

		foreach ($this->params as $paramName => $paramValue) {
			if ($paramName == 'pg_items') {
				//$itemsElement = $xmlElement->addChild($paramName);
				foreach ($paramValue as $itemParams) {
					$itemElement = $xmlElement->addChild($paramName);
					foreach ($itemParams as $itemParamName => $itemParamValue) {
						$itemElement->addChild($itemParamName, $itemParamValue);
					}
				}
				continue;
			}

			$xmlElement->addChild($paramName, $paramValue);
		}

		return $xmlElement->asXML();
	}
}


class OfdReceiptItem
{
	public $label;
	public $amount;
	public $price;
	public $quantity;
	public $vat;

	public function toArray()
	{
		return array(
			'pg_label' => extension_loaded('mbstring') ? mb_substr($this->label, 0, 128) : substr($this->label, 0, 128),
			#'pg_amount' => $this->amount,
			'pg_price' => $this->price,
			'pg_quantity' => $this->quantity,
			'pg_vat' => $this->vat,
		);
	}
}


