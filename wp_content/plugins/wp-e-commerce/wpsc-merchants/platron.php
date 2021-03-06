<?php
$nzshpcrt_gateways[$num]['name'] = __( 'Platron', 'wpsc' );
$nzshpcrt_gateways[$num]['internalname'] = 'platron';
$nzshpcrt_gateways[$num]['function'] = 'gateway_platron';
$nzshpcrt_gateways[$num]['form'] = "form_platron";
$nzshpcrt_gateways[$num]['submit_function'] = "submit_platron";
$nzshpcrt_gateways[$num]['display_name'] = __( 'Platron', 'wpsc' );
$nzshpcrt_gateways[$num]['image'] = WPSC_URL . '/images/platron.png';

require_once 'platron/PG_Signature.php';

// создание транзакции
function gateway_platron($separator, $sessionid)
{
	global $wpdb;
	$purchase_log_sql = $wpdb->prepare( "SELECT * FROM `".WPSC_TABLE_PURCHASE_LOGS."` WHERE `sessionid`= %s LIMIT 1", $sessionid );
	$purchase_log = $wpdb->get_results($purchase_log_sql,ARRAY_A) ;

	$strCartSql = "SELECT * FROM `".WPSC_TABLE_CART_CONTENTS."` WHERE `purchaseid`='".$purchase_log[0]['id']."'";
	$arrCartItems = $wpdb->get_results($strCartSql,ARRAY_A) ;

	$base_shipping = $purchase_log[0]['base_shipping'];

	$arrEmailData = $wpdb->get_results("SELECT `id`,`type` FROM `".WPSC_TABLE_CHECKOUT_FORMS."` WHERE `name` IN ('email','Email') AND `active` = '1'",ARRAY_A);
	foreach((array)$arrEmailData as $email)
    	$strEmail = $_POST['collected_data'][$email['id']];

  	if(($_POST['collected_data'][get_option('email_form_field')] != null) && ($strEmail == null))
    	$strEmail = $_POST['collected_data'][get_option('email_form_field')];

	$arrPhoneData = $wpdb->get_results("SELECT `id`,`type` FROM `".WPSC_TABLE_CHECKOUT_FORMS."` WHERE `name` IN ('phone','Phone') AND `active` = '1'",ARRAY_A);
	foreach((array)$arrPhoneData as $phone)
    	$strPhone = $_POST['collected_data'][$phone['id']];

  	if(($_POST['collected_data'][get_option('phone_form_field')] != null) && ($strPhone == null))
    	$strPhone = $_POST['collected_data'][get_option('phone_form_field')];
	
	$strDescription = '';
	foreach($arrCartItems as $arrItem){
		$strDescription .= $arrItem['name'];
		if($arrItem['quantity'] > 1)
			$strDescription .= '*'.$arrItem['quantity']."; ";
		else
			$strDescription .= "; ";
	}

	$strUrlToCallBack = add_query_arg( 'platron_callback', 'true', home_url( '/index.php' ) ) . "&session_id=" . $sessionid;

	$arrFields = array(
		'pg_merchant_id'		=> get_option( 'merchant_id' ),
		'pg_order_id'			=> $purchase_log[0]['id'],
		'pg_currency'			=> get_local_currency_code(), # WPSC_Countries::get_currency_code( get_option( 'currency_type' )),
		'pg_amount'				=> number_format($purchase_log[0]['totalprice'], 2, '.', ''),
		'pg_user_phone'			=> $strPhone,
		'pg_user_email'			=> $strEmail,
		'pg_user_contact_email'	=> $strEmail,
		'pg_lifetime'			=> (get_option( 'lifetime' ))?get_option('lifetime')*60:0,
		'pg_testing_mode'		=> get_option( 'testmode' ),
		'pg_description'		=> $strDescription ? $strDescription : '-',
		'pg_language'			=> (WPLANG == 'ru_RU')?'ru':'en',
		'pg_check_url'			=> $strUrlToCallBack . '&type=check',
		'pg_result_url'			=> $strUrlToCallBack . '&type=result',
		'pg_request_method'		=> 'GET',
		'pg_salt'				=> rand(21,43433), // Параметры безопасности сообщения. Необходима генерация pg_salt и подписи сообщения.
	);
	
	$strSuccessUrl = get_option( 'success_url' );
	if(isset($strSuccessUrl))
		$arrFields['pg_success_url'] = $strSuccessUrl;

	$strFailureUrl = get_option( 'failure_url' );
	if(isset($strFailureUrl))
		$arrFields['pg_failure_url'] = $strFailureUrl;
		
	$strPaymentSystemName = get_option( 'payment_system_name' );
	if(!empty($strPaymentSystemName))
		$arrFields['pg_payment_system'] = $strPaymentSystemName;
	
	$arrFields['cms_payment_module'] = 'WP_E_COMMERCE';
	$arrFields['pg_sig'] = PG_Signature::make('init_payment.php', $arrFields, get_option( 'secret_key' ));

	if(WPSC_GATEWAY_DEBUG == true ) {
		exit("<pre>".print_r($arrFields,true)."</pre>");
	}

	$response = file_get_contents('https://www.platron.ru/init_payment.php' . '?' . http_build_query($arrFields));
	$responseElement = new SimpleXMLElement($response);

	$checkResponse = PG_Signature::checkXML('init_payment.php', $responseElement, get_option( 'secret_key' ));

	if ($checkResponse && (string)$responseElement->pg_status == 'ok') {

   		if (get_option( 'create_ofd_check' ) == 1) {

   			$paymentId = (string)$responseElement->pg_payment_id;

   	        $ofdReceiptItems = array();
   	        foreach($arrCartItems as $item){
       		    $ofdReceiptItem = new OfdReceiptItem();
   	            $ofdReceiptItem->label = $item['name'];
       		    $ofdReceiptItem->amount = round($item['price'] * $item['quantity'], 2);
   	            $ofdReceiptItem->price = round($item['price'], 2);
       		    $ofdReceiptItem->quantity = $item['quantity'];
   	            $ofdReceiptItem->vat = get_option( 'ofd_vat_type' );
       		    $ofdReceiptItems[] = $ofdReceiptItem;
   	        }

            if ($base_shipping > 0) {
       		    $ofdReceiptItem = new OfdReceiptItem();
   	            $ofdReceiptItem->label = $purchase_log[0]['shipping_option'] ? $purchase_log[0]['shipping_option'] : 'Shipping';
       		    $ofdReceiptItem->amount = round($base_shipping, 2);
   	            $ofdReceiptItem->price = round($base_shipping, 2);
       		    $ofdReceiptItem->quantity = 1;
   	            $ofdReceiptItem->vat = get_option( 'ofd_vat_type' ) == 'none'? 'none': '20';
		    $ofdReceiptItem->type = 'service';
       		    $ofdReceiptItems[] = $ofdReceiptItem;
			}			

   			$ofdReceiptRequest = new OfdReceiptRequest(get_option( 'merchant_id' ), $paymentId);
   			$ofdReceiptRequest->items = $ofdReceiptItems;
   			$ofdReceiptRequest->sign(get_option( 'secret_key' ));

   			$responseOfd = file_get_contents('https://www.platron.ru/receipt.php' . '?' . http_build_query($ofdReceiptRequest->requestArray()));
   			$responseElementOfd = new SimpleXMLElement($responseOfd);

   			if ((string)$responseElementOfd->pg_status != 'ok') {
   				die('Platron check create error. ' . $responseElementOfd->pg_error_description);
   			}
   		}

	} else {

		die('Platron init payment error. ' . $responseElement->pg_error_description);

	}

	$arrFields['pg_sig'] = PG_Signature::make('payment.php', $arrFields, get_option( 'secret_key' ));


	// Create Form to post to Platron
	$output = "
		<form id=\"platron_form\" name=\"platron_form\" method=\"post\" action=\"" . $responseElement->pg_redirect_url . "\">\n";

	foreach($arrFields as $strName=>$strValue) {
			$output .= "			<input type=\"hidden\" name=\"$strName\" value=\"$strValue\" />\n";
	}

	$output .= "			<input type=\"submit\" value=\"Pay\" />
		</form>
		<script language=\"javascript\" type=\"text/javascript\">document.getElementById('platron_form').submit();</script>
	";

	echo $output;
  	exit();
}

function get_local_currency_code() {
	global $wpdb;
	return $wpdb->get_var( $wpdb->prepare( "SELECT `code` FROM `" . WPSC_TABLE_CURRENCY_LIST . "` WHERE `id`= %d LIMIT 1", get_option( 'currency_type' ) ) );
}


function nzshpcrt_platron_callback()
{
		
	if(isset($_GET['platron_callback']))
	{
			
		global $wpdb;
		// needs to execute on page start
		// look at page 36
		
		if(!empty($_POST))
			$arrRequest = $_POST;
		else
			$arrRequest = $_GET;
	
		$thisScriptName = PG_Signature::getOurScriptName();
		if (empty($arrRequest['pg_sig']) || !PG_Signature::check($arrRequest['pg_sig'], $thisScriptName, $arrRequest, get_option( 'secret_key' )))
			die("Wrong signature");
			
		
		$arrAllStatuses = array(
			'1' => 'pending',
			'2'	=> 'completed',
			'3' => 'ok',
			'4' => 'processed',
			'5'	=> 'closed',
			'6' => 'rejected',
		);
		$aGoodCheckStatuses = array(
			'1' => 'pending',
			'4' => 'processed',
		);
		
		$aGoodResultStatuses = array(
			'1' => 'pending',
			'2'	=> 'completed',
			'3' => 'ok',
			'4' => 'processed',	
		);
		
		$purchase_log_sql = $wpdb->prepare( "SELECT * FROM `".WPSC_TABLE_PURCHASE_LOGS."` WHERE `id`= %s LIMIT 1", $arrRequest['pg_order_id'] );
		$purchase_log = $wpdb->get_results($purchase_log_sql,ARRAY_A);
		$nRealOrderStatus = $purchase_log[0]['processed'];
		$nTotalPrice = $purchase_log[0]['totalprice'];
		
		switch($arrRequest['type']){
			case 'check':
				$bCheckResult = 1;			
				if(empty($purchase_log) || !array_key_exists($nRealOrderStatus, $aGoodCheckStatuses)){
					$bCheckResult = 0;
					$error_desc = 'Order status '.$arrAllStatuses[$nRealOrderStatus].' or deleted order';
				}
				if(intval($nTotalPrice) != intval($arrRequest['pg_amount'])){
					$bCheckResult = 0;
					$error_desc = 'Wrong amount';
				}

				$arrResponse['pg_salt']              = $arrRequest['pg_salt']; 
				$arrResponse['pg_status']            = $bCheckResult ? 'ok' : 'error';
				$arrResponse['pg_error_description'] = $bCheckResult ?  ""  : $error_desc;
				$arrResponse['pg_sig']				 = PG_Signature::make($thisScriptName, $arrResponse, get_option( 'secret_key' ));

				$objResponse = new SimpleXMLElement('<?xml version="1.0" encoding="utf-8"?><response/>');
				$objResponse->addChild('pg_salt', $arrResponse['pg_salt']);
				$objResponse->addChild('pg_status', $arrResponse['pg_status']);
				$objResponse->addChild('pg_error_description', $arrResponse['pg_error_description']);
				$objResponse->addChild('pg_sig', $arrResponse['pg_sig']);
				break;
			case 'result':
				if(intval($nTotalPrice) != intval($arrRequest['pg_amount'])){
					$strResponseDescription = 'Wrong amount';
					if($arrRequest['pg_can_reject'] == 1)
						$strResponseStatus = 'rejected';
					else
						$strResponseStatus = 'error';
				}
				elseif((empty($purchase_log) || !array_key_exists($nRealOrderStatus, $aGoodResultStatuses)) && 
						!($arrRequest['pg_result'] == 0 && $nRealOrderStatus == array_search('failed', $arrAllStatuses))){
					$strResponseDescription = 'Order status '.$arrAllStatuses[$nRealOrderStatus].' or deleted order';
					if($arrRequest['pg_can_reject'] == 1)
						$strResponseStatus = 'rejected';
					else
						$strResponseStatus = 'error';
				} else {
					$strResponseStatus = 'ok';
					$strResponseDescription = "Request cleared";
					if ($arrRequest['pg_result'] == 1){
						$data = array(
							'processed'  => array_search('ok', $arrAllStatuses),
							'transactid' => $arrRequest['pg_transaction_id'],
							'date'       => time(),
						);
						wpsc_update_purchase_log_details( $arrRequest['session_id'], $data, 'sessionid' );
					}
					else{
						$data = array(
							'processed'  => array_search('rejected', $arrAllStatuses),
							'transactid' => $arrRequest['pg_transaction_id'],
							'date'       => time(),
						);
						wpsc_update_purchase_log_details( $arrRequest['session_id'], $data, 'sessionid' );						
					}
				}
				transaction_results($arrRequest['session_id'], false, $arrRequest['pg_transaction_id']);
				
				$objResponse = new SimpleXMLElement('<?xml version="1.0" encoding="utf-8"?><response/>');
				$objResponse->addChild('pg_salt', $arrRequest['pg_salt']);
				$objResponse->addChild('pg_status', $strResponseStatus);
				$objResponse->addChild('pg_description', $strResponseDescription);
				$objResponse->addChild('pg_sig', PG_Signature::makeXML($thisScriptName, $objResponse, get_option( 'secret_key' )));
				break;
			default:
				die('Wrong type request');
				break;
		}
		
		header("Content-type: text/xml");
		echo $objResponse->asXML();
		die();
	}
}

function nzshpcrt_platron_results()
{
	// Function used to translate the ChronoPay returned cs1=sessionid POST variable into the recognised GET variable for the transaction results page.
	if(isset($_POST['cs1']) && ($_POST['cs1'] !='') && ($_GET['sessionid'] == ''))
	{
		$_GET['sessionid'] = $_POST['cs1'];
	}
}


// сохранение формы из админки
function submit_platron()
{
	if(isset($_POST['merchant_id']))
    {
    	update_option('merchant_id', $_POST['merchant_id']);
    }

	if(isset($_POST['secret_key']))
    {
    	update_option('secret_key', $_POST['secret_key']);
    }

  	if(isset($_POST['testmode']))
    {
    	update_option('testmode', $_POST['testmode']);
    }

  	if(isset($_POST['lifetime']))
    {
    	update_option('lifetime', $_POST['lifetime']);
    }
	
	 if(isset($_POST['success_url']))
    {
    	update_option('success_url', $_POST['success_url']);
    }
	
	 if(isset($_POST['failure_url']))
    {
    	update_option('failure_url', $_POST['failure_url']);
    }

 	if(isset($_POST['payment_system_name']))
    {
    	update_option('payment_system_name', $_POST['payment_system_name']);
    }

  	if(isset($_POST['ofd_vat_type']))
    {
    	update_option('ofd_vat_type', $_POST['ofd_vat_type']);
    }

  	if(isset($_POST['create_ofd_check']))
    {
    	update_option('create_ofd_check', $_POST['create_ofd_check']);
    }

	return true;
}

// вывод полей в админке
function form_platron()
{
	$platron_testmode = get_option('testmode');
	$platron_create_ofd_check = get_option('create_ofd_check');
    $platron_ofd_vat_type = get_option( 'ofd_vat_type' );

	$testmode_yes = "";
	$testmode_no = "";
	$create_ofd_check_yes = "";
	$create_ofd_check_no = "";

	switch($platron_testmode)
	{
		case 1:
			$testmode_yes = "checked ='checked'";
			break;
		case 0:
			$testmode_no = "checked ='checked'";
			break;
	}

	switch($platron_create_ofd_check)
	{
		case 1:
			$create_ofd_check_yes = "checked ='checked'";
			break;
		case 0:
			$create_ofd_check_no = "checked ='checked'";
			break;
	}

	$output = "
		<tr>
			<td>" . __( 'Merchant ID', 'wpsc' ) . "</td>
			<td>
				<input type='text' size='40' value='" . get_option( 'merchant_id' ) . "' name='merchant_id' />
				<p class='description'>
					" . __( 'Your merchant number. You can find it in the platron <a href="https://platron.ru/admin/merchants.php">admin</a>.', 'wpsc' ) . "
				</p>
			</td>
		</tr>
		<tr>
			<td>" . __( 'Secret key', 'wpsc' ) . "</td>
			<td>
				<input type='text' size='40' value='" . get_option( 'secret_key' ) . "' name='secret_key' />
				<p class='description'>
					" . __( 'This key will be used to make signature.', 'wpsc' ) . "
				</p>
		</tr>
		<tr>
			<td>" . __( 'Testing mode', 'wpsc' ) . "</td>
			<td>
				<input type='radio' value='1' name='testmode' id='testmode_yes' " . $testmode_yes . " /> <label for='testmode_yes'>".__('Yes', 'wpsc')."</label> &nbsp;
				<input type='radio' value='0' name='testmode' id='testmode_no' " . $testmode_no . " /> <label for='testmode_no'>".__('No', 'wpsc')."</label>
				<p class='description'>
					" . __( 'Debug mode is used to write HTTP communications between the ChronoPay server and your host to a log file.  This should only be activated for testing!', 'wpsc' ) . "
				</p>
		</tr>
		<tr>
			<td>" . __( 'Transaction life time', 'wpsc' ) . "</td>
			<td>
				<input type='text' size='40' value='" . get_option( 'lifetime' ) . "' name='lifetime' />
				<p class='description'>
					" . __( 'If payment system dont support check or reject you need to set payment lifetime. Min 5 minute max 10800 (7 days).', 'wpsc' ) . "
				</p>
		</tr>
		<tr>
			<td>" . __( 'Success url', 'wpsc' ) . "</td>
			<td>
				<input type='text' size='80' value='" . get_option( 'success_url' ) . "' name='success_url' />
				<p class='description'>
					" . __( 'Url, where customer returned to see success transaction result. You can set it as example: www.your.domain/?page_id=7 (page customer account to see purchase result) or other page', 'wpsc' ) . "
				</p>
		</tr>
		<tr>
			<td>" . __( 'Failure url', 'wpsc' ) . "</td>
			<td>
				<input type='text' size='80' value='" . get_option( 'failure_url' ) . "' name='failure_url' />
				<p class='description'>
					" . __( 'Url, where customer returned to see failed transaction result. You can set it as example: www.your.domain/?page_id=7 (page customer account to see purchase result) or other page', 'wpsc' ) . "
				</p>
		</tr>
		<tr>
			<td>" . __( 'Payment system name', 'wpsc' ) . "</td>
			<td>
				<input type='text' size='40' value='" . get_option( 'payment_system_name' ) . "' name='payment_system_name' />
				<p class='description'>
					" . __( 'If you want customer to choose payment system on merchant side - set in paramenter. And copy plugin with rename "platron" so many times so many payment systems you have.', 'wpsc' ) . "
				</p>
		</tr>
		<tr>
			<td>" . __( 'Create OFD check', 'wpsc' ) . "</td>
			<td>
				<input type='radio' value='1' name='create_ofd_check' id='create_ofd_check_yes' " . $create_ofd_check_yes . " /> <label for='create_ofd_check_yes'>".__('Yes', 'wpsc')."</label> &nbsp;
				<input type='radio' value='0' name='create_ofd_check' id='create_ofd_check_no' "  . $create_ofd_check_no . " /> <label for='create_ofd_check_no'>".__('No', 'wpsc')."</label>
				<p class='description'>
					" . __( 'Create check for OFD. Used in Used for 54-FZ law.', 'wpsc' ) . "
				</p>
		</tr>
		<tr>
			<td>" . __( 'ODFD VAT type', 'wpsc' ) . "</td>
			<td>
                <select name='ofd_vat_type' id='ofd_vat_type'>
                    <option value='0' "  . ($platron_ofd_vat_type == '0'  or !$platron_ofd_vat_type ? 'selected' : '') . ">0%</option>
                    <option value='10'"  . ($platron_ofd_vat_type == '10'  ? 'selected' : '') . ">10%</option>
                    <option value='20'"  . ($platron_ofd_vat_type == '20'  ? 'selected' : '') . ">20%</option>
                    <option value='110'" . ($platron_ofd_vat_type == '110' ? 'selected' : '') . ">10/110%</option>
                    <option value='120'" . ($platron_ofd_vat_type == '120' ? 'selected' : '') . ">20/120%</option>
		    <option value='none'" . ($platron_ofd_vat_type == 'none' ? 'selected' : '') . ">Не облагается
		    </option>
                </select>
				<p class='description'>
					" . __( 'VAT type for OFD.', 'wpsc' ) . "
				</p>
		</tr>";

	return $output;
}


add_action('init', 'nzshpcrt_platron_callback');
add_action('init', 'nzshpcrt_platron_results');

?>
