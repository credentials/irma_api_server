/*
 * Copyright (c) 2015, the IRMA Team
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the IRMA project nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.irmacard.api.web;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.TestProperties;
import org.glassfish.jersey.test.jetty.JettyTestContainerFactory;
import org.irmacard.api.common.*;
import org.irmacard.credentials.idemix.IdemixCredential;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.info.IdemixKeyStoreDeserializer;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.idemix.proofs.ProofListBuilder;
import org.irmacard.credentials.idemix.proofs.ProofD;
import org.irmacard.credentials.info.*;
import org.irmacard.api.common.DisclosureProofResult.Status;
import org.irmacard.api.common.util.GsonUtil;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.File;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class VerificationTest extends JerseyTest {
	public static final String schemeManager = "irma-demo";

	public VerificationTest() {
		super(new JettyTestContainerFactory());
	}

	@BeforeClass
	public static void initializeInformation() throws InfoException {
		URI core = new File(System.getProperty("user.dir")).toURI().resolve("src/main/resources/irma_configuration/");
		DescriptionStore.initialize(new DescriptionStoreDeserializer(core));
		IdemixKeyStore.initialize(new IdemixKeyStoreDeserializer(core));
	}

	@Override
	protected void configureClient(ClientConfig config) {
		config.register(GsonJerseyProvider.class);
	}

	@Override
	protected Application configure() {
		enable(TestProperties.LOG_TRAFFIC);
		enable(TestProperties.DUMP_ENTITY);
		return new ApiApplication();
	}

	public String createSession() throws InfoException {
		AttributeDisjunctionList attrs = new AttributeDisjunctionList(1);
		attrs.add(new AttributeDisjunction("Over 12", schemeManager + ".MijnOverheid.ageLower.over12"));
		DisclosureProofRequest request = new DisclosureProofRequest(null, null, attrs);
		ServiceProviderRequest spRequest = new ServiceProviderRequest("testrequest", request, 60);

		ClientQr qr = target("/verification/").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(spRequest, MediaType.APPLICATION_JSON), ClientQr.class);

		String sessiontoken = qr.getUrl();

		assert(sessiontoken.length() > 20);
		return sessiontoken;
	}

	public void doSession(List<Integer> disclosed, Status expectedResult)
	throws InfoException, KeyManagementException {
		IdemixCredential cred = getAgeLowerCredential();
		String session = createSession();
		DisclosureProofRequest request = target("/verification/" + session).request(MediaType.APPLICATION_JSON)
				.get(DisclosureProofRequest.class);

		// Create the proof and post it
		ProofList proofs = new ProofListBuilder(request.getContext(), request.getNonce())
				.addProofD(cred, disclosed)
				.build();
		Status status = target("/verification/" + session + "/proofs").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(proofs, MediaType.APPLICATION_JSON), Status.class);
		assert(status == expectedResult);

		// Fetch the JSON web token containing the attributes
		String jwt = target("/verification/" + session + "/getproof").request(MediaType.TEXT_PLAIN).get(String.class);

		// Verify the token itself, and that the credential was valid
		PublicKey pk = ApiConfiguration.getInstance().getJwtPublicKey();
		Claims body = Jwts.parser().setSigningKey(pk).parseClaimsJws(jwt).getBody();

		assert body.get("status").toString().equals(expectedResult.name());
	}

	@Test
	public void validSessionTest() throws InfoException, KeyManagementException {
		doSession(Arrays.asList(1, 2), Status.VALID);
	}

	@Test
	public void missingAttributesTest() throws InfoException, KeyManagementException {
		doSession(Collections.singletonList(1), Status.MISSING_ATTRIBUTES);
	}

	@Test
	public void missingMetadataTest() throws InfoException, KeyManagementException {
		doSession(Arrays.asList(2, 3), Status.INVALID);
	}

	@Test
	@SuppressWarnings("unused")
	public void missingProofTest() throws InfoException, KeyManagementException {
		String session = createSession();
		DisclosureProofRequest request = target("/verification/" + session).request(MediaType.APPLICATION_JSON)
				.get(DisclosureProofRequest.class);

		// Fetch the JSON web token
		String jwt = target("/verification/" + session + "/getproof").request(MediaType.TEXT_PLAIN).get(String.class);

		// Verify the token itself, and that the credential was valid
		PublicKey pk = ApiConfiguration.getInstance().getJwtPublicKey();
		Claims body = Jwts.parser().setSigningKey(pk).parseClaimsJws(jwt).getBody();

		assert body.get("status").toString().equals("WAITING");
	}

	@Test
	@SuppressWarnings("unused")
	public void brokenProofTest() throws InfoException, KeyManagementException {
		String session = createSession();
		DisclosureProofRequest request = target("/verification/" + session).request(MediaType.APPLICATION_JSON)
				.get(DisclosureProofRequest.class);

		Response response = target("/verification/" + session + "/proofs").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity("{\"foo\": 1}", MediaType.APPLICATION_JSON));

		assert(response.getStatus() == 400);
	}

	@Test
	@SuppressWarnings("unused")
	public void brokenJsonTest() throws InfoException, KeyManagementException {
		String session = createSession();
		DisclosureProofRequest request = target("/verification/" + session).request(MediaType.APPLICATION_JSON)
				.get(DisclosureProofRequest.class);

		Response response = target("/verification/" + session + "/proofs").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity("{\"foo\": 1", MediaType.APPLICATION_JSON));

		assert(response.getStatus() == 400);
	}

	@Test
	public void invalidProofTest()
	throws InfoException, KeyManagementException, NoSuchFieldException, IllegalAccessException {
		IdemixCredential cred = getAgeLowerCredential();
		String session = createSession();
		DisclosureProofRequest request = target("/verification/" + session).request(MediaType.APPLICATION_JSON)
				.get(DisclosureProofRequest.class);

		// Create the proof
		List<Integer> disclosed = Arrays.asList(2, 3);
		ProofList proofs = new ProofListBuilder(request.getContext(), request.getNonce())
				.addProofD(cred, disclosed)
				.build();

		// Dirty hackz0rs to invalidate the proof
		Field f = ProofD.class.getDeclaredField("A");
		f.setAccessible(true);
		f.set(proofs.get(0), BigInteger.TEN);

		Status status = target("/verification/" + session + "/proofs").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(proofs, MediaType.APPLICATION_JSON), Status.class);
		assert(status == Status.INVALID);

		// Fetch the JSON web token containing the attributes
		String jwt = target("/verification/" + session + "/getproof").request(MediaType.TEXT_PLAIN).get(String.class);

		// Verify the token itself, and that the credential was valid
		PublicKey pk = ApiConfiguration.getInstance().getJwtPublicKey();
		Claims body = Jwts.parser().setSigningKey(pk).parseClaimsJws(jwt).getBody();

		assert body.get("status").toString().equals("INVALID");
	}

	@Test
	public void boundProofsTest() throws InfoException, KeyManagementException {
		IdemixCredential cred1 = getAgeLowerCredential();
		IdemixCredential cred2 = getNameCredential();

		AttributeDisjunctionList attrs = new AttributeDisjunctionList(1);
		attrs.add(new AttributeDisjunction("Over 12", schemeManager + ".MijnOverheid.ageLower.over12"));
		attrs.add(new AttributeDisjunction("Name", schemeManager + ".MijnOverheid.fullName.firstname"));
		DisclosureProofRequest request = new DisclosureProofRequest(null, null, attrs);

		ServiceProviderRequest spRequest = new ServiceProviderRequest("testrequest", request, 60);

		ClientQr qr = target("/verification/").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(spRequest, MediaType.APPLICATION_JSON), ClientQr.class);

		String session = qr.getUrl();

		request = target("/verification/" + session).request(MediaType.APPLICATION_JSON).get(DisclosureProofRequest.class);

		// Create the proof and post it;
		ProofList proofs = new ProofListBuilder(request.getContext(), request.getNonce())
				.addProofD(cred1, Arrays.asList(1, 2))
				.addProofD(cred2, Arrays.asList(1, 3))
				.build();
		Status status = target("/verification/" + session + "/proofs").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(proofs, MediaType.APPLICATION_JSON), Status.class);
		assert(status == Status.VALID);

		// Fetch the JSON web token containing the attributes
		String jwt = target("/verification/" + session + "/getproof").request(MediaType.TEXT_PLAIN).get(String.class);

		// Verify the token itself, and that the credential was valid
		PublicKey pk = ApiConfiguration.getInstance().getJwtPublicKey();
		Claims body = Jwts.parser().setSigningKey(pk).parseClaimsJws(jwt).getBody();

		assert body.get("status").toString().equals("VALID");
	}


	public IdemixCredential getAgeLowerCredential() {
		String json = "{\"attributes\":[83969732886137331441367901401499190192021186657517570791631111325428115654231,49043385373240779928272317727814162106733085467653777386,7955827,7955827,7955827,7955827],\"issuer_pk\":{\"R\":[75350858539899247205099195870657569095662997908054835686827949842616918065279527697469302927032348256512990413925385972530386004430200361722733856287145745926519366823425418198189091190950415327471076288381822950611094023093577973125683837586451857056904547886289627214081538422503416179373023552964235386251,16493273636283143082718769278943934592373185321248797185217530224336539646051357956879850630049668377952487166494198481474513387080523771033539152347804895674103957881435528189990601782516572803731501616717599698546778915053348741763191226960285553875185038507959763576845070849066881303186850782357485430766,13291821743359694134120958420057403279203178581231329375341327975072292378295782785938004910295078955941500173834360776477803543971319031484244018438746973179992753654070994560440903251579649890648424366061116003693414594252721504213975050604848134539324290387019471337306533127861703270017452296444985692840,86332479314886130384736453625287798589955409703988059270766965934046079318379171635950761546707334446554224830120982622431968575935564538920183267389540869023066259053290969633312602549379541830869908306681500988364676409365226731817777230916908909465129739617379202974851959354453994729819170838277127986187,68324072803453545276056785581824677993048307928855083683600441649711633245772441948750253858697288489650767258385115035336890900077233825843691912005645623751469455288422721175655533702255940160761555155932357171848703103682096382578327888079229101354304202688749783292577993444026613580092677609916964914513,65082646756773276491139955747051924146096222587013375084161255582716233287172212541454173762000144048198663356249316446342046266181487801411025319914616581971563024493732489885161913779988624732795125008562587549337253757085766106881836850538709151996387829026336509064994632876911986826959512297657067426387],\"S\":68460510129747727135744503403370273952956360997532594630007762045745171031173231339034881007977792852962667675924510408558639859602742661846943843432940752427075903037429735029814040501385798095836297700111333573975220392538916785564158079116348699773855815825029476864341585033111676283214405517983188761136,\"Z\":44579327840225837958738167571392618381868336415293109834301264408385784355849790902532728798897199236650711385876328647206143271336410651651791998475869027595051047904885044274040212624547595999947339956165755500019260290516022753290814461070607850420459840370288988976468437318992206695361417725670417150636,\"counter\":0,\"expiryDate\":\"April 6, 2017 2:00:00 AM GMT+02:00\",\"n\":96063359353814070257464989369098573470645843347358957127875426328487326540633303185702306359400766259130239226832166456957259123554826741975265634464478609571816663003684533868318795865194004795637221226902067194633407757767792795252414073029114153019362701793292862118990912516058858923030408920700061749321,\"systemParameters\":{\"l_e\":597,\"l_e_commit\":456,\"l_e_prime\":120,\"l_h\":256,\"l_m\":256,\"l_m_commit\":592,\"l_n\":1024,\"l_r_a\":1104,\"l_s_commit\":593,\"l_statzk\":80,\"l_v\":1700,\"l_v_commit\":2036,\"l_v_prime\":1104,\"l_v_prime_commit\":1440,\"size_a_response\":74,\"size_e\":75,\"size_e_response\":117,\"size_h\":32,\"size_m\":32,\"size_n\":128,\"size_s_response\":75,\"size_statzk\":10,\"size_v\":213,\"size_v_response\":255}},\"signature\":{\"A\":13917686307669050390136579208319249902078512653172573624400224720730039470888467871145278468713804708839748850058871409680420709222589241727861995538026294097275260304877354484038954387449799585713213037668818790636642392755579567758035009584099169672075870449125951700650814202529251266457620648833725292036,\"e\":259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930109316689984557065871505665515754017,\"v\":53722392980005588453267998299015980836134854151017196213054887727720778902992497114503715191221936267379987210314073089614275288966516155193900741321803298500089823817210872442405652561256418111610819988142923328145485639584787975151322662271638128395551459727048738552308916254749371854536876022261087320801160129014372805448695588403443876991878551708850149154022531736352241884182635678272179847460141451499125631233192724996064584060338080288707422864327145427454210938607548127684160985309414861395989852020}}";

		return GsonUtil.getGson().fromJson(json, IdemixCredential.class);
	}

	public IdemixCredential getNameCredential() {
		String json = "{\"attributes\":[83969732886137331441367901401499190192021186657517570791631111325428115654231,49043385373240779963703399947578252570418315037715050678,6014105876062937174,1400268142,426883701167904661398898,32],\"issuer_pk\":{\"R\":[75350858539899247205099195870657569095662997908054835686827949842616918065279527697469302927032348256512990413925385972530386004430200361722733856287145745926519366823425418198189091190950415327471076288381822950611094023093577973125683837586451857056904547886289627214081538422503416179373023552964235386251,16493273636283143082718769278943934592373185321248797185217530224336539646051357956879850630049668377952487166494198481474513387080523771033539152347804895674103957881435528189990601782516572803731501616717599698546778915053348741763191226960285553875185038507959763576845070849066881303186850782357485430766,13291821743359694134120958420057403279203178581231329375341327975072292378295782785938004910295078955941500173834360776477803543971319031484244018438746973179992753654070994560440903251579649890648424366061116003693414594252721504213975050604848134539324290387019471337306533127861703270017452296444985692840,86332479314886130384736453625287798589955409703988059270766965934046079318379171635950761546707334446554224830120982622431968575935564538920183267389540869023066259053290969633312602549379541830869908306681500988364676409365226731817777230916908909465129739617379202974851959354453994729819170838277127986187,68324072803453545276056785581824677993048307928855083683600441649711633245772441948750253858697288489650767258385115035336890900077233825843691912005645623751469455288422721175655533702255940160761555155932357171848703103682096382578327888079229101354304202688749783292577993444026613580092677609916964914513,65082646756773276491139955747051924146096222587013375084161255582716233287172212541454173762000144048198663356249316446342046266181487801411025319914616581971563024493732489885161913779988624732795125008562587549337253757085766106881836850538709151996387829026336509064994632876911986826959512297657067426387],\"S\":68460510129747727135744503403370273952956360997532594630007762045745171031173231339034881007977792852962667675924510408558639859602742661846943843432940752427075903037429735029814040501385798095836297700111333573975220392538916785564158079116348699773855815825029476864341585033111676283214405517983188761136,\"Z\":44579327840225837958738167571392618381868336415293109834301264408385784355849790902532728798897199236650711385876328647206143271336410651651791998475869027595051047904885044274040212624547595999947339956165755500019260290516022753290814461070607850420459840370288988976468437318992206695361417725670417150636,\"counter\":0,\"expiryDate\":\"April 6, 2017 2:00:00 AM GMT+02:00\",\"n\":96063359353814070257464989369098573470645843347358957127875426328487326540633303185702306359400766259130239226832166456957259123554826741975265634464478609571816663003684533868318795865194004795637221226902067194633407757767792795252414073029114153019362701793292862118990912516058858923030408920700061749321,\"systemParameters\":{\"l_e\":597,\"l_e_commit\":456,\"l_e_prime\":120,\"l_h\":256,\"l_m\":256,\"l_m_commit\":592,\"l_n\":1024,\"l_r_a\":1104,\"l_s_commit\":593,\"l_statzk\":80,\"l_v\":1700,\"l_v_commit\":2036,\"l_v_prime\":1104,\"l_v_prime_commit\":1440,\"size_a_response\":74,\"size_e\":75,\"size_e_response\":117,\"size_h\":32,\"size_m\":32,\"size_n\":128,\"size_s_response\":75,\"size_statzk\":10,\"size_v\":213,\"size_v_response\":255}},\"signature\":{\"A\":29121687402465135363694951678908207561389873833440269302524401780174710009527543531536180019101422888780486402008520805474661959349608300788715991806524432311747680081538051638954169696739988155692931002173812149571139940538905857240817922599675640901687132799087275093816313807764514187195402199049974344024,\"e\":259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930244137080829929094898740309637574359,\"v\":35308161573339520995570229232781808440046911071747849510142921088324588843376062317133651255890105846693159671052408739516673692694015900412084689641101686189961947845000550362226259328442364330102730837209553433412447637795509263315347229261472814441963315462921948660787402285027641629868640245554123344567765766685509312746245663664540062877173590636643724021619689213330271643409413686451270769589106680750270056907154008119443957954495199131114982177352533439278052095692787846084429372445003678183685417795}}";

		return GsonUtil.getGson().fromJson(json, IdemixCredential.class);
	}
}
