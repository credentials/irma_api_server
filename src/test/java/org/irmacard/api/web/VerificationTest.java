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
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.TestProperties;
import org.glassfish.jersey.test.jetty.JettyTestContainerFactory;
import org.irmacard.api.common.*;
import org.irmacard.api.common.DisclosureProofResult.Status;
import org.irmacard.api.common.util.GsonUtil;
import org.irmacard.credentials.idemix.IdemixCredential;
import org.irmacard.credentials.idemix.proofs.ProofD;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.idemix.proofs.ProofListBuilder;
import org.irmacard.credentials.info.InfoException;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.ws.rs.ForbiddenException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.KeyManagementException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

public class VerificationTest extends JerseyTest {
	public static final String schemeManager = "irma-demo";
	private static String configuration;

	public VerificationTest() {
		super(new JettyTestContainerFactory());

		ApiConfiguration.instance = GsonUtil.getGson().fromJson(configuration, ApiConfiguration.class);
		ApiConfiguration.instance.hot_reload_configuration = false;
	}

	@BeforeClass
	public static void initializeInformation() throws InfoException {
		ApiConfiguration.testing = true;

		try {
			configuration = new String(ApiConfiguration.getResource("config.test.json"));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
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

	public String createSession() throws KeyManagementException {
		return createSession(System.currentTimeMillis() / 1000,
				ApiConfiguration.getInstance().getPrivateKey("test-sk.der"));
	}

	public String createSession(long issuedAt, PrivateKey jwtPrivateKey) throws KeyManagementException {
		AttributeDisjunctionList attrs = new AttributeDisjunctionList(1);
		attrs.add(new AttributeDisjunction("Over 12", schemeManager + ".MijnOverheid.ageLower.over12"));
		DisclosureProofRequest request = new DisclosureProofRequest(null, null, attrs);

		return createSession(request, issuedAt, jwtPrivateKey);
	}

	public String createSession(DisclosureProofRequest request) throws KeyManagementException {
		return createSession(request, System.currentTimeMillis() / 1000,
				ApiConfiguration.getInstance().getPrivateKey("test-sk.der"));
	}

	public String createSession(DisclosureProofRequest request, long issuedAt, PrivateKey jwtPrivateKey)
	throws KeyManagementException {
		ServiceProviderRequest spRequest = new ServiceProviderRequest("testrequest", request, 60);

		Map<String, Object> claims = new HashMap<>();
		claims.put("sprequest", spRequest);
		claims.put("iss", "testsp");
		claims.put("sub", "verification_request");
		claims.put("iat", issuedAt);

		JwtBuilder builder = Jwts.builder().setPayload(GsonUtil.getGson().toJson(claims));
		if (jwtPrivateKey != null)
			builder.signWith(ApiConfiguration.getInstance().getJwtAlgorithm(), jwtPrivateKey);
		String jwt = builder.compact();

		ClientQr qr = target("/verification/").request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(jwt, MediaType.TEXT_PLAIN), ClientQr.class);

		System.out.println(qr.getUrl());
		return qr.getUrl();
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
		// Prepare the session
		AttributeDisjunctionList attrs = new AttributeDisjunctionList(1);
		attrs.add(new AttributeDisjunction("Over 12", schemeManager + ".MijnOverheid.ageLower.over12"));
		attrs.add(new AttributeDisjunction("Name", schemeManager + ".MijnOverheid.fullName.firstname"));
		DisclosureProofRequest request = new DisclosureProofRequest(null, null, attrs);

		// Create the session
		String session = createSession(request);
		request = target("/verification/" + session).request(MediaType.APPLICATION_JSON).get(DisclosureProofRequest.class);

		IdemixCredential cred1 = getAgeLowerCredential();
		IdemixCredential cred2 = getNameCredential();

		// Create the proof and post it
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
		String json = "{\"attributes\":[112961990642791461386728772516135531828308105460336295493922754493540509231566,49043424930035004139509278706172805511124944437643913194,7955827,7955827,7955827,28271],\"issuer_pk\":{\"R\":[75350858539899247205099195870657569095662997908054835686827949842616918065279527697469302927032348256512990413925385972530386004430200361722733856287145745926519366823425418198189091190950415327471076288381822950611094023093577973125683837586451857056904547886289627214081538422503416179373023552964235386251,16493273636283143082718769278943934592373185321248797185217530224336539646051357956879850630049668377952487166494198481474513387080523771033539152347804895674103957881435528189990601782516572803731501616717599698546778915053348741763191226960285553875185038507959763576845070849066881303186850782357485430766,13291821743359694134120958420057403279203178581231329375341327975072292378295782785938004910295078955941500173834360776477803543971319031484244018438746973179992753654070994560440903251579649890648424366061116003693414594252721504213975050604848134539324290387019471337306533127861703270017452296444985692840,86332479314886130384736453625287798589955409703988059270766965934046079318379171635950761546707334446554224830120982622431968575935564538920183267389540869023066259053290969633312602549379541830869908306681500988364676409365226731817777230916908909465129739617379202974851959354453994729819170838277127986187,68324072803453545276056785581824677993048307928855083683600441649711633245772441948750253858697288489650767258385115035336890900077233825843691912005645623751469455288422721175655533702255940160761555155932357171848703103682096382578327888079229101354304202688749783292577993444026613580092677609916964914513,65082646756773276491139955747051924146096222587013375084161255582716233287172212541454173762000144048198663356249316446342046266181487801411025319914616581971563024493732489885161913779988624732795125008562587549337253757085766106881836850538709151996387829026336509064994632876911986826959512297657067426387],\"S\":68460510129747727135744503403370273952956360997532594630007762045745171031173231339034881007977792852962667675924510408558639859602742661846943843432940752427075903037429735029814040501385798095836297700111333573975220392538916785564158079116348699773855815825029476864341585033111676283214405517983188761136,\"Z\":44579327840225837958738167571392618381868336415293109834301264408385784355849790902532728798897199236650711385876328647206143271336410651651791998475869027595051047904885044274040212624547595999947339956165755500019260290516022753290814461070607850420459840370288988976468437318992206695361417725670417150636,\"counter\":0,\"expiryDate\":\"April 6, 2017 2:00:00 AM GMT+02:00\",\"n\":96063359353814070257464989369098573470645843347358957127875426328487326540633303185702306359400766259130239226832166456957259123554826741975265634464478609571816663003684533868318795865194004795637221226902067194633407757767792795252414073029114153019362701793292862118990912516058858923030408920700061749321},\"signature\":{\"A\":68533701937873128482737818560475183892036216568419752089077224694240212254205668108304847382273430745052974745393682332508226890926177547490172324164602652105810724166782213760290045939371815866449699025364173534769235545671591470942754925667257339559864498041398553594067900747584640023828171706340674817759,\"e\":259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742929730886373219009073122877672881849999,\"v\":29518891402015970778270151554204282549181182074657780092038808897646746043219476464224341755809937990855929812529412254350383892442161124710568809215166513999849736424967708622224751931801664912668708090824042913167326668438316585908677095075411656867171366175087992866350736272544056790551184560175275962570694737794794455107944205152251966874642810242052036878823788491859616029361526260753685973571793455709848023078473282710540290560651579243262482551920625310149229554147859074254548555314954105446262902357}}";

		return GsonUtil.getGson().fromJson(json, IdemixCredential.class);
	}

	public IdemixCredential getNameCredential() {
		String json = "{\"attributes\":[112961990642791461386728772516135531828308105460336295493922754493540509231566,49043424930035004174940360925936895974810174007705186486,23036574416140583473985643890,319696691566,394104700814284069891684,7758190],\"issuer_pk\":{\"R\":[75350858539899247205099195870657569095662997908054835686827949842616918065279527697469302927032348256512990413925385972530386004430200361722733856287145745926519366823425418198189091190950415327471076288381822950611094023093577973125683837586451857056904547886289627214081538422503416179373023552964235386251,16493273636283143082718769278943934592373185321248797185217530224336539646051357956879850630049668377952487166494198481474513387080523771033539152347804895674103957881435528189990601782516572803731501616717599698546778915053348741763191226960285553875185038507959763576845070849066881303186850782357485430766,13291821743359694134120958420057403279203178581231329375341327975072292378295782785938004910295078955941500173834360776477803543971319031484244018438746973179992753654070994560440903251579649890648424366061116003693414594252721504213975050604848134539324290387019471337306533127861703270017452296444985692840,86332479314886130384736453625287798589955409703988059270766965934046079318379171635950761546707334446554224830120982622431968575935564538920183267389540869023066259053290969633312602549379541830869908306681500988364676409365226731817777230916908909465129739617379202974851959354453994729819170838277127986187,68324072803453545276056785581824677993048307928855083683600441649711633245772441948750253858697288489650767258385115035336890900077233825843691912005645623751469455288422721175655533702255940160761555155932357171848703103682096382578327888079229101354304202688749783292577993444026613580092677609916964914513,65082646756773276491139955747051924146096222587013375084161255582716233287172212541454173762000144048198663356249316446342046266181487801411025319914616581971563024493732489885161913779988624732795125008562587549337253757085766106881836850538709151996387829026336509064994632876911986826959512297657067426387],\"S\":68460510129747727135744503403370273952956360997532594630007762045745171031173231339034881007977792852962667675924510408558639859602742661846943843432940752427075903037429735029814040501385798095836297700111333573975220392538916785564158079116348699773855815825029476864341585033111676283214405517983188761136,\"Z\":44579327840225837958738167571392618381868336415293109834301264408385784355849790902532728798897199236650711385876328647206143271336410651651791998475869027595051047904885044274040212624547595999947339956165755500019260290516022753290814461070607850420459840370288988976468437318992206695361417725670417150636,\"counter\":0,\"expiryDate\":\"April 6, 2017 2:00:00 AM GMT+02:00\",\"n\":96063359353814070257464989369098573470645843347358957127875426328487326540633303185702306359400766259130239226832166456957259123554826741975265634464478609571816663003684533868318795865194004795637221226902067194633407757767792795252414073029114153019362701793292862118990912516058858923030408920700061749321},\"signature\":{\"A\":11779744863721756617511144187152694865710152069627768211557490047802915919649710124618782903864204210298380302272140814546705507287985134366526502234815911565509460050828301370450039393057360290468978166045345277925800331912435630296669370071820100743460450509536525501674924362287593592540007717403416055502,\"e\":259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742929830282842257990678188843053513037601,\"v\":44716574490357249881234067468598298561612894769525135315635663473002516385728818584921138976298445084425574602879042502783814780511121856498101320530325263762554242673548740180382875589938486155132156911366584541512345452540478607547723352804840792279711318151887854632372068896668556782223682580301915629767633980002145017239751315903971862922892251176121872276177569912204087952663180650818855732112604837643578693067903557475134302499934322165163555265963936653379706036096489932444086329677209261382320899247}}";

		return GsonUtil.getGson().fromJson(json, IdemixCredential.class);
	}

	/* Configuration tests ******************************************/

	@Test(expected=NotAuthorizedException.class)
	public void shouldBeJwtTest() throws InfoException, KeyManagementException {
		ApiConfiguration.getInstance().allow_unsigned_verification_requests = false;
		createSession(System.currentTimeMillis() / 1000, null);
	}

	@Test
	public void unsignedJwt() throws KeyManagementException {
		ApiConfiguration.getInstance().allow_unsigned_verification_requests = true;
		createSession(System.currentTimeMillis() / 1000, null);
	}

	@Test(expected=NotAuthorizedException.class)
	public void oldJwtTest() throws KeyManagementException {
		ApiConfiguration.getInstance().allow_unsigned_verification_requests = false;
		createSession(1, ApiConfiguration.getInstance().getPrivateKey("test-sk.der"));
	}

	@Test(expected=NotAuthorizedException.class)
	public void wrongJwtKeyTest() throws KeyManagementException {
		ApiConfiguration.getInstance().allow_unsigned_verification_requests = false;
		createSession(System.currentTimeMillis() / 1000,
				ApiConfiguration.instance.getPrivateKey("sk.der"));
	}

	@Test
	public void authorizedVerifierTest() throws KeyManagementException {
		ApiConfiguration.getInstance().allow_unsigned_verification_requests = false;
		ApiConfiguration.instance.authorized_sps.put("testsp", new ArrayList<String>());
		try {
			createSession();
		} catch (ForbiddenException e) { /* Expected */ }

		ApiConfiguration.instance.authorized_sps.get("testsp").add(schemeManager+".MijnOverheid.ageLower.over12");
		createSession();

		ApiConfiguration.instance.authorized_sps.get("testsp").set(0, schemeManager+".*");
		createSession();

		ApiConfiguration.instance.authorized_sps.get("testsp").set(0, schemeManager+".MijnOverheid.*");
		createSession();

		ApiConfiguration.instance.authorized_sps.get("testsp").set(0, schemeManager+".MijnOverheid.ageLower.*");
		createSession();
	}
}
