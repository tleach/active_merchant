require 'test_helper'
require 'digest/sha1'
require 'xmlsimple'

class RealexTest < Test::Unit::TestCase
  
  class ActiveMerchant::Billing::RealexGateway
    # For the purposes of testing, lets redefine some protected methods as public.
    public :build_purchase_or_authorization_request, :build_refund_request, :build_void_request, :build_capture_request, :avs_input_code,
           :build_add_payer_request, :build_add_payment_method_request, :build_delete_payment_method_request, :build_receipt_in_request,
           :build_payment_out_request
  end
  
  def setup
    @login = 'your_merchant_id'
    @password = 'your_secret'
    @account = 'your_account'
    @rebate_secret = 'your_rebate_secret'
  
    @gateway = RealexGateway.new(
      :login => @login,
      :password => @password,
      :account => @account
    )

    @gateway_with_account = RealexGateway.new(
      :login => @merchant_id,
      :password => @secret,
      :account => 'bill_web_cengal'
    )
    
    @credit_card = CreditCard.new(
      :number => '4263971921001307',
      :month => 8,
      :year => 2008,
      :first_name => 'Longbob',
      :last_name => 'Longsen',
      :type => 'visa'
    )
    
    @options = {
      :order_id => '1'
    }
    
    @address = {
      :name => 'Longbob Longsen',
      :address1 => '123 Fake Street',
      :city => 'Belfast',
      :state => 'Antrim',
      :country => 'Northern Ireland',
      :zip => 'BT2 8XX'
    }
    
    @amount = 100
  end
  
  
  def test_in_test
    assert_equal :test, ActiveMerchant::Billing::Base.gateway_mode
  end  
  
  def test_hash
    gateway = RealexGateway.new(
      :login => 'thestore',
      :password => 'mysecret'
    )
    Time.stubs(:now).returns(Time.parse("2001-04-03 12:32:45"))
    gateway.expects(:ssl_post).with(anything, regexp_matches(/9af7064afd307c9f988e8dfc271f9257f1fc02f6/)).returns(successful_purchase_response)
    gateway.purchase(29900, credit_card('5105105105105100'), :order_id => 'ORD453-11')
  end

  def test_successful_purchase
    @gateway.expects(:ssl_post).returns(successful_purchase_response)
    
    response = @gateway.purchase(@amount, @credit_card, @options)
    assert_instance_of Response, response
    assert_success response
    assert response.test?
  end
  
  def test_unsuccessful_purchase
    @gateway.expects(:ssl_post).returns(unsuccessful_purchase_response)
    
    response = @gateway.purchase(@amount, @credit_card, @options)
    assert_instance_of Response, response
    assert_failure response
    assert response.test?
  end

  def test_successful_purchase_with_stored_card
    @gateway.expects(:ssl_post).with(){|endpoint, data|
      'receipt-in' == XmlSimple.xml_in(data)['type'] 
      }.returns(successful_plugin_response)

    response = @gateway.purchase(@amount, 333, @options)
    assert_instance_of Response, response
    assert_success response
  end
  
  def test_successful_refund
    @gateway.expects(:ssl_post).returns(successful_refund_response)    
    assert_success @gateway.refund(@amount, '1234;1234;1234')
  end
  
  def test_unsuccessful_refund
    @gateway.expects(:ssl_post).returns(unsuccessful_refund_response)
    assert_failure @gateway.refund(@amount, '1234;1234;1234')
  end

  def test_deprecated_credit
    @gateway.expects(:ssl_post).returns(successful_refund_response)
    assert_deprecation_warning(Gateway::CREDIT_DEPRECATION_MESSAGE, @gateway) do
      assert_success @gateway.credit(@amount, '1234;1234;1234')
    end
  end

  def test_store
    @gateway.expects(:ssl_post).with(){|endpoint, data|
      'payer-new' == XmlSimple.xml_in(data)['type'] &&
      "https://epage.payandshop.com/epage-remote-plugins.cgi" == endpoint
      }.returns(successful_plugin_response)
    @gateway.expects(:ssl_post).with(){|endpoint, data|
      'card-new' == XmlSimple.xml_in(data)['type'] &&
      "https://epage.payandshop.com/epage-remote-plugins.cgi" == endpoint
      }.returns(successful_plugin_response)
    response = @gateway.store(@credit_card, {:customer => 1})
    assert_instance_of Response, response
    assert_success response
  end
  
  def test_unsuccessful_store
    @gateway.expects(:ssl_post).with(){|endpoint, data|
      'payer-new' == XmlSimple.xml_in(data)['type'] &&
      "https://epage.payandshop.com/epage-remote-plugins.cgi" == endpoint
      }.returns(unsuccessful_plugin_response)
    response = @gateway.store(@credit_card, {:customer => 1})
    assert_instance_of Response, response
    assert_failure response
  end

  def test_unstore
    @gateway.expects(:ssl_post).with(){|endpoint, data|
      'card-cancel-card'.eql?(XmlSimple.xml_in(data)['type']) &&
      "https://epage.payandshop.com/epage-remote-plugins.cgi" == endpoint
      }.returns(successful_plugin_response)
    response = @gateway.unstore(1)
    assert_instance_of Response, response
    assert_success response
  end

  def test_unsuccessful_unstore
    @gateway.expects(:ssl_post).with(){|endpoint, data|
      'card-cancel-card'.eql?(XmlSimple.xml_in(data)['type']) &&
      "https://epage.payandshop.com/epage-remote-plugins.cgi" == endpoint
      }.returns(unsuccessful_plugin_response)
    response = @gateway.unstore(1)
    assert_instance_of Response, response
    assert_failure response
  end

  def test_supported_countries
    assert_equal ['IE', 'GB'], RealexGateway.supported_countries
  end
  
  def test_supported_card_types
    assert_equal [ :visa, :master, :american_express, :diners_club, :switch, :solo, :laser ], RealexGateway.supported_cardtypes
  end
  
  def test_avs_result_not_supported
    @gateway.expects(:ssl_post).returns(successful_purchase_response)
  
    response = @gateway.purchase(@amount, @credit_card, @options)
    assert_nil response.avs_result['code']
  end
  
  def test_cvv_result
    @gateway.expects(:ssl_post).returns(successful_purchase_response)
  
    response = @gateway.purchase(@amount, @credit_card, @options)
    assert_equal 'M', response.cvv_result['code']
  end
  
  def test_capture_xml
    @gateway.expects(:new_timestamp).returns('20090824160201')
    
    valid_capture_xml = <<-SRC
<request timestamp="20090824160201" type="settle">
  <merchantid>your_merchant_id</merchantid>
  <account>your_account</account>
  <orderid>1</orderid>
  <pasref>4321</pasref>
  <authcode>1234</authcode>
  <sha1hash>4132600f1dc70333b943fc292bd0ca7d8e722f6e</sha1hash>
</request>
SRC
    
    assert_xml_equal valid_capture_xml, @gateway.build_capture_request('1;4321;1234', {})
  end
  
  def test_purchase_xml
    options = {
      :order_id => '1'
    }

    @gateway.expects(:new_timestamp).returns('20090824160201')

    valid_purchase_request_xml = <<-SRC
<request timestamp="20090824160201" type="auth">
  <merchantid>your_merchant_id</merchantid>
  <account>your_account</account>
  <orderid>1</orderid>
  <amount currency="EUR">100</amount>
  <card>
    <number>4263971921001307</number>
    <expdate>0808</expdate>
    <chname>Longbob Longsen</chname>
    <type>VISA</type>
    <issueno></issueno>
    <cvn>
      <number></number>
      <presind></presind>
    </cvn>
  </card>
  <autosettle flag="1"/>
  <sha1hash>3499d7bc8dbacdcfba2286bd74916d026bae630f</sha1hash>
</request>
SRC

    assert_xml_equal valid_purchase_request_xml, @gateway.build_purchase_or_authorization_request(:purchase, @amount, @credit_card, options)
  end
  
  def test_void_xml
    @gateway.expects(:new_timestamp).returns('20090824160201')

    valid_void_request_xml = <<-SRC
<request timestamp="20090824160201" type="void">
  <merchantid>your_merchant_id</merchantid>
  <account>your_account</account>
  <orderid>1</orderid>
  <pasref>4321</pasref>
  <authcode>1234</authcode>
  <sha1hash>4132600f1dc70333b943fc292bd0ca7d8e722f6e</sha1hash>
</request>
SRC

    assert_xml_equal valid_void_request_xml, @gateway.build_void_request('1;4321;1234', {})
  end
  
  def test_auth_xml
    options = {
      :order_id => '1'
    }

    @gateway.expects(:new_timestamp).returns('20090824160201')

    valid_auth_request_xml = <<-SRC
<request timestamp="20090824160201" type="auth">
  <merchantid>your_merchant_id</merchantid>
  <account>your_account</account>
  <orderid>1</orderid>
  <amount currency=\"EUR\">100</amount>
  <card>
    <number>4263971921001307</number>
    <expdate>0808</expdate>
    <chname>Longbob Longsen</chname>
    <type>VISA</type>
    <issueno></issueno>
    <cvn>
      <number></number>
      <presind></presind>
    </cvn>
  </card>
  <autosettle flag="0"/>
  <sha1hash>3499d7bc8dbacdcfba2286bd74916d026bae630f</sha1hash>
</request>
SRC

    assert_xml_equal valid_auth_request_xml, @gateway.build_purchase_or_authorization_request(:authorization, @amount, @credit_card, options)
  end
  
  def test_refund_xml
    @gateway.expects(:new_timestamp).returns('20090824160201')

    valid_refund_request_xml = <<-SRC
<request timestamp="20090824160201" type="rebate">
  <merchantid>your_merchant_id</merchantid>
  <account>your_account</account>
  <orderid>1</orderid>
  <pasref>4321</pasref>
  <authcode>1234</authcode>
  <amount currency="EUR">100</amount>
  <autosettle flag="1"/>
  <sha1hash>ef0a6c485452f3f94aff336fa90c6c62993056ca</sha1hash>
</request>
SRC

    assert_xml_equal valid_refund_request_xml, @gateway.build_refund_request(@amount, '1;4321;1234', {})

  end
  
  def test_refund_with_rebate_secret_xml
    gateway = RealexGateway.new(:login => @login, :password => @password, :account => @account, :rebate_secret => @rebate_secret)
    
    gateway.expects(:new_timestamp).returns('20090824160201')

    valid_refund_request_xml = <<-SRC
<request timestamp="20090824160201" type="rebate">
  <merchantid>your_merchant_id</merchantid>
  <account>your_account</account>
  <orderid>1</orderid>
  <pasref>4321</pasref>
  <authcode>1234</authcode>
  <amount currency="EUR">100</amount>
  <refundhash>f94ff2a7c125a8ad87e5683114ba1e384889240e</refundhash>
  <autosettle flag="1"/>
  <sha1hash>ef0a6c485452f3f94aff336fa90c6c62993056ca</sha1hash>
</request>
SRC

    assert_xml_equal valid_refund_request_xml, gateway.build_refund_request(@amount, '1;4321;1234', {})

  end

  def test_add_payer_xml
    gateway = RealexGateway.new(:login => @login, :password => @password, :account => @account, :rebate_secret => @rebate_secret)

    # First test the method when the optional order ID is included.
    options = {
      :order_id => '1',
      :customer => 'Longbob_Longsen'
    }

    gateway.expects(:new_timestamp).returns('20090824160201')

    valid_add_payer_xml = <<-SRC
<request timestamp="20090824160201" type="payer-new">
  <merchantid>your_merchant_id</merchantid>
  <orderid>1</orderid>
  <payer type="Business" ref="Longbob_Longsen">
    <firstname>Longbob</firstname>
    <surname>Longsen</surname>
  </payer>
  <sha1hash>940846325851cfb37bfc1bf36318980609837d2c</sha1hash>
</request>
SRC
    
    assert_xml_equal valid_add_payer_xml, gateway.build_add_payer_request(@credit_card, options)

    # Test the method with the order ID omitted
    options = {
      :customer => 'Longbob_Longsen'
    }

    gateway.expects(:new_timestamp).returns('20090824160201')

    valid_add_payer_xml = <<-SRC
<request timestamp="20090824160201" type="payer-new">
  <merchantid>your_merchant_id</merchantid>
  <payer type="Business" ref="Longbob_Longsen">
    <firstname>Longbob</firstname>
    <surname>Longsen</surname>
  </payer>
  <sha1hash>56b1d48eacf4d7bf135a3866b52491f47a5fadcb</sha1hash>
</request>
SRC
    
    assert_xml_equal valid_add_payer_xml, gateway.build_add_payer_request(@credit_card, options)
  end
  
  def test_add_payment_method_xml
    gateway = RealexGateway.new(:login => @login, :password => @password, :account => @account, :rebate_secret => @rebate_secret)

    options = {
      :order_id => '1',
      :customer => 'Longbob_Longsen'
    }

    gateway.expects(:new_timestamp).returns('20090824160201')

    valid_add_payment_method_xml = <<-SRC
<request timestamp="20090824160201" type="card-new">
  <merchantid>your_merchant_id</merchantid>
  <orderid>1</orderid>
  <card>
    <ref>1</ref>
    <payerref>Longbob_Longsen</payerref>
    <number>4263971921001307</number>
    <expdate>0808</expdate>
    <chname>Longbob Longsen</chname>
    <type>VISA</type>
    <issueno />
  </card>
  <sha1hash>2e88b9d3b173a1b00a70476743a696c651ce35bb</sha1hash>
</request>
SRC
    
    assert_xml_equal valid_add_payment_method_xml, gateway.build_add_payment_method_request(@credit_card, options)

    options = {
      :customer => 'Longbob_Longsen'
    }

    gateway.expects(:new_timestamp).returns('20090824160201')

    valid_add_payment_method_xml = <<-SRC
<request timestamp="20090824160201" type="card-new">
  <merchantid>your_merchant_id</merchantid>
  <card>
    <ref>1</ref>
    <payerref>Longbob_Longsen</payerref>
    <number>4263971921001307</number>
    <expdate>0808</expdate>
    <chname>Longbob Longsen</chname>
    <type>VISA</type>
    <issueno />
  </card>
  <sha1hash>51b91abe9787206e4bd6af6ad1802858052db375</sha1hash>
</request>
SRC
    
    assert_xml_equal valid_add_payment_method_xml, gateway.build_add_payment_method_request(@credit_card, options)
  end

  def test_delete_payment_method_xml
    gateway = RealexGateway.new(:login => @login, :password => @password, :account => @account, :rebate_secret => @rebate_secret)

    gateway.expects(:new_timestamp).returns('20090824160201')

    valid_delete_payment_method_xml = <<-SRC
<request timestamp="20090824160201" type="card-cancel-card">
  <merchantid>your_merchant_id</merchantid>
  <card>
    <ref>1</ref>
    <payerref>Longbob_Longsen</payerref>
  </card>
  <sha1hash>2c9cbca68b3694ed5ebe6fa44d289b3599aa2112</sha1hash>
</request>
SRC
    
    assert_xml_equal valid_delete_payment_method_xml, gateway.build_delete_payment_method_request('Longbob_Longsen')    
  end

  def test_receipt_in_xml
    gateway = RealexGateway.new(:login => @login, :password => @password, :account => @account, :rebate_secret => @rebate_secret)

    gateway.expects(:new_timestamp).returns('20090824160201')

    valid_receipt_in_xml = <<-SRC
<request type="receipt-in" timestamp="20090824160201"> 
  <merchantid>your_merchant_id</merchantid> 
  <account>your_account</account> 
  <amount currency="AUD">9999</amount> 
  <payerref>33</payerref> 
  <paymentmethod>1</paymentmethod> 
  <autosettle flag="1" /> 
  <sha1hash>8561c62727b670676a49b2a2577832592991d117</sha1hash> 
</request>
SRC
    
    assert_xml_equal(
      valid_receipt_in_xml, 
      gateway.build_receipt_in_request(33, 9999, {:currency => 'AUD'}))
  end

  # Test we can build the payment-out XML fragment used to pay out a refund from a stored card. 
  def test_payment_out_xml
    gateway = RealexGateway.new(:login => @login, :password => @password, :account => @account, :rebate_secret => @rebate_secret)

    gateway.expects(:new_timestamp).returns('20090824160201')

    valid_payment_out_xml = <<-SRC
<request type="payment-out" timestamp="20090824160201"> 
  <merchantid>your_merchant_id</merchantid> 
  <account>your_account</account> 
  <amount currency="AUD">9999</amount> 
  <payerref>33</payerref> 
  <paymentmethod>1</paymentmethod> 
  <refundhash>f94ff2a7c125a8ad87e5683114ba1e384889240e</refundhash> 
  <sha1hash>8561c62727b670676a49b2a2577832592991d117</sha1hash> 
</request>
SRC
    
    assert_xml_equal(
      valid_payment_out_xml, 
      gateway.build_payment_out_request(33, 9999, {:currency => 'AUD'}))
  end

  def test_should_extract_avs_input
    address = {:address1 => "123 Fake Street", :zip => 'BT1 0HX'}
    assert_equal "10|123", @gateway.avs_input_code(address)
  end

  def test_auth_with_address
    @gateway.expects(:ssl_post).returns(successful_purchase_response)
    
    options = {
      :order_id => '1',
      :billing_address => @address,
      :shipping_address => @address
    }

    @gateway.expects(:new_timestamp).returns('20090824160201')
    
    response = @gateway.authorize(@amount, @credit_card, options)
    assert_instance_of Response, response
    assert_success response
    assert response.test?
    
  end

  def test_zip_in_shipping_address
    @gateway.expects(:ssl_post).with(anything, regexp_matches(/<code>BT28XX<\/code>/)).returns(successful_purchase_response)
    
    options = {
      :order_id => '1',
      :billing_address => @address,
      :shipping_address => @address
    }

    @gateway.authorize(@amount, @credit_card, options)
  end


  private
  
  def successful_purchase_response
    <<-RESPONSE
<response timestamp='20010427043422'>
  <merchantid>your merchant id</merchantid>
  <account>account to use</account>
  <orderid>order id from request</orderid>
  <authcode>authcode received</authcode>
  <result>00</result>
  <message>[ test system ] message returned from system</message>
  <pasref> realex payments reference</pasref>
  <cvnresult>M</cvnresult>
  <batchid>batch id for this transaction (if any)</batchid>
  <cardissuer>
    <bank>Issuing Bank Name</bank>
    <country>Issuing Bank Country</country>
    <countrycode>Issuing Bank Country Code</countrycode>
    <region>Issuing Bank Region</region>
  </cardissuer>
  <tss>
    <result>89</result>
    <check id="1000">9</check>
    <check id="1001">9</check>
  </tss>
  <sha1hash>7384ae67....ac7d7d</sha1hash>
  <md5hash>34e7....a77d</md5hash>
</response>"
    RESPONSE
  end
  
  def unsuccessful_purchase_response
    <<-RESPONSE
<response timestamp='20010427043422'>
  <merchantid>your merchant id</merchantid>
  <account>account to use</account>
  <orderid>order id from request</orderid>
  <authcode>authcode received</authcode>
  <result>01</result>
  <message>[ test system ] message returned from system</message>
  <pasref> realex payments reference</pasref>
  <cvnresult>M</cvnresult>
  <batchid>batch id for this transaction (if any)</batchid>
  <cardissuer>
    <bank>Issuing Bank Name</bank>
    <country>Issuing Bank Country</country>
    <countrycode>Issuing Bank Country Code</countrycode>
    <region>Issuing Bank Region</region>
  </cardissuer>
  <tss>
    <result>89</result>
    <check id="1000">9</check>
    <check id="1001">9</check>
  </tss>
  <sha1hash>7384ae67....ac7d7d</sha1hash>
  <md5hash>34e7....a77d</md5hash>
</response>"
    RESPONSE
  end
  
  def successful_refund_response
    <<-RESPONSE
<response timestamp='20010427043422'>
  <merchantid>your merchant id</merchantid>
  <account>account to use</account>
  <orderid>order id from request</orderid>
  <authcode>authcode received</authcode>
  <result>00</result>
  <message>[ test system ] message returned from system</message>
  <pasref> realex payments reference</pasref>
  <cvnresult>M</cvnresult>
  <batchid>batch id for this transaction (if any)</batchid>
  <sha1hash>7384ae67....ac7d7d</sha1hash>
  <md5hash>34e7....a77d</md5hash>
</response>"
    RESPONSE
  end

  def unsuccessful_refund_response
    <<-RESPONSE
<response timestamp='20010427043422'>
  <merchantid>your merchant id</merchantid>
  <account>account to use</account>
  <orderid>order id from request</orderid>
  <authcode>authcode received</authcode>
  <result>508</result>
  <message>[ test system ] You may only rebate up to 115% of the original amount.</message>
  <pasref> realex payments reference</pasref>
  <cvnresult>M</cvnresult>
  <batchid>batch id for this transaction (if any)</batchid>
  <sha1hash>7384ae67....ac7d7d</sha1hash>
  <md5hash>34e7....a77d</md5hash>
</response>"
    RESPONSE
  end

  def successful_plugin_response
    <<-RESPONSE
<response timestamp="20030520152009"> 
  <merchantid>your_merchant_id</merchantid> 
  <account>myvisa</account> 
  <orderid>20030428-018</orderid> 
  <result>00</result> 
  <message>Authorised</message> 
  <pasref>PAS Reference</pasref> 
  <batchid>Batch ID</batchid> 
  <timetaken>Time taken in seconds</timetaken> 
  <sha1hash>cdaea87dc26c852b6420e5419d765f45e9974e19</sha1hash> 
</response>
    RESPONSE
  end

  def unsuccessful_plugin_response
    <<-RESPONSE
<response timestamp="20080619112622"> 
<result>502</result> 
<message>Type 'payer-new' not implemented. Please check the Developer 
Documentation for allowed 
types</message> 
<orderid>transaction01</orderid> 
</response>
    RESPONSE
  end

  def assert_xml_equal(expected, actual)
    assert_equal XmlSimple.xml_in(expected), XmlSimple.xml_in(actual)
  end
end