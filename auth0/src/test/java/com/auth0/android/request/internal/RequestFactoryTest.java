package com.auth0.android.request.internal;

import com.auth0.android.Auth0;
import com.auth0.android.Auth0Exception;
import com.auth0.android.request.ErrorBuilder;
import com.auth0.android.request.ParameterizableRequest;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.OkHttpClient;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Locale;
import java.util.Map;

import static com.auth0.android.request.internal.RequestMatcher.hasArguments;
import static com.auth0.android.request.internal.RequestMatcher.hasHeaders;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

public class RequestFactoryTest {

    private static final String METHOD_POST = "POST";
    private static final String METHOD_PATCH = "PATCH";
    private static final String METHOD_DELETE = "DELETE";
    private static final String METHOD_GET = "GET";
    private static final String CLIENT_INFO = "client_info";
    private static final String USER_AGENT = "user_agent";
    private static final String TOKEN = "token";
    private static final String BEARER_PREFIX = "Bearer ";
    private RequestFactory factory;

    @Mock
    private OkHttpClient client;
    private Gson gson;
    @Mock
    private ErrorBuilder<Auth0Exception> builder;
    private HttpUrl url;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        gson = new Gson();
        url = HttpUrl.parse("http://domain.auth0.com");
        factory = createBaseFactory();
    }

    @Test
    public void shouldHaveNonNullHeaders() {
        final RequestFactory factory = new RequestFactory();

        assertThat(factory.getHeaders(), is(notNullValue()));
    }

    @Test
    public void shouldHaveAcceptLanguageHeader() {
        final RequestFactory factory = new RequestFactory();

        assertThat(factory.getHeaders().size(), is(1));
        assertThat(factory.getHeaders().get("Accept-Language"), is(equalTo(RequestFactory.getDefaultLocale())));
    }

    @Test
    public void shouldHaveClientInfoHeader() {
        final RequestFactory factory = new RequestFactory();

        factory.setClientInfo(CLIENT_INFO);
        assertThat(factory.getHeaders().size(), is(2));
        assertThat(factory.getHeaders().get("Auth0-Client"), is(equalTo(CLIENT_INFO)));
    }

    @Test
    public void shouldHaveUserAgentHeader() {
        final RequestFactory factory = new RequestFactory();

        factory.setUserAgent(USER_AGENT);
        assertThat(factory.getHeaders().size(), is(2));
        assertThat(factory.getHeaders().get("User-Agent"), is(equalTo(USER_AGENT)));
    }

    @Test
    public void shouldHaveAuthorizationHeader() {
        final RequestFactory factory = new RequestFactory(TOKEN);

        assertThat(factory.getHeaders().size(), is(2));
        assertThat(factory.getHeaders().get("Authorization"), is(equalTo(BEARER_PREFIX + TOKEN)));
    }

    @Test
    public void shouldCreateAuthenticationPOSTRequest() {
        final MockAuthenticationRequest request = (MockAuthenticationRequest) factory.authenticationPOST(url, client, gson);

        assertThat(request, is(notNullValue()));
        assertThat(request, AuthenticationRequestMatcher.hasHeaders(RequestFactory.getDefaultLocale(), CLIENT_INFO, USER_AGENT));
        assertThat(request, AuthenticationRequestMatcher.hasArguments(url, METHOD_POST));
    }

    @Test
    public void shouldCreatePOSTRequestOfTClass() {
        ParameterizableRequest<Auth0, Auth0Exception> request = factory.POST(url, client, gson, Auth0.class, builder);

        assertThat(request, is(notNullValue()));
        assertThat(request, hasHeaders(RequestFactory.getDefaultLocale(), CLIENT_INFO, USER_AGENT));
        assertThat(request, RequestMatcher.hasArguments(url, METHOD_POST, Auth0.class));
    }

    @Test
    public void shouldCreatePOSTRequestOfTToken() {
        TypeToken<Auth0> typeToken = createTypeToken();
        final ParameterizableRequest<Auth0, Auth0Exception> request = factory.POST(url, client, gson, typeToken, builder);

        assertThat(request, is(notNullValue()));
        assertThat(request, hasHeaders(RequestFactory.getDefaultLocale(), CLIENT_INFO, USER_AGENT));
        assertThat(request, RequestMatcher.hasArguments(url, METHOD_POST, typeToken));
    }

    @Test
    public void shouldCreateVoidPOSTRequest() {
        final ParameterizableRequest<Void, Auth0Exception> request = factory.POST(url, client, gson, builder);

        assertThat(request, is(notNullValue()));
        assertThat(request, hasHeaders(RequestFactory.getDefaultLocale(), CLIENT_INFO, USER_AGENT));
        assertThat(request, hasArguments(url, METHOD_POST));
    }

    @Test
    public void shouldCreateRawPOSTRequest() {
        final ParameterizableRequest<Map<String, Object>, Auth0Exception> request = factory.rawPOST(url, client, gson, builder);

        assertThat(request, is(notNullValue()));
        assertThat(request, hasHeaders(RequestFactory.getDefaultLocale(), CLIENT_INFO, USER_AGENT));
        assertThat(request, hasArguments(url, METHOD_POST));
    }

    @Test
    public void shouldCreatePATCHRequestOfTClass() {
        final ParameterizableRequest<Auth0, Auth0Exception> request = factory.PATCH(url, client, gson, Auth0.class, builder);

        assertThat(request, is(notNullValue()));
        assertThat(request, hasHeaders(RequestFactory.getDefaultLocale(), CLIENT_INFO, USER_AGENT));
        assertThat(request, RequestMatcher.hasArguments(url, METHOD_PATCH, Auth0.class));
    }

    @Test
    public void shouldCreateDELETERequestOfTToken() {
        TypeToken<Auth0> typeToken = createTypeToken();
        final ParameterizableRequest<Auth0, Auth0Exception> request = factory.DELETE(url, client, gson, typeToken, builder);

        assertThat(request, is(notNullValue()));
        assertThat(request, hasHeaders(RequestFactory.getDefaultLocale(), CLIENT_INFO, USER_AGENT));
        assertThat(request, RequestMatcher.hasArguments(url, METHOD_DELETE, typeToken));
    }

    @Test
    public void shouldCreateGETRequest() {
        final ParameterizableRequest<Auth0, Auth0Exception> request = factory.GET(url, client, gson, Auth0.class, builder);

        assertThat(request, is(notNullValue()));
        assertThat(request, hasHeaders(RequestFactory.getDefaultLocale(), CLIENT_INFO, USER_AGENT));
        assertThat(request, RequestMatcher.hasArguments(url, METHOD_GET, Auth0.class));
    }

    @Test
    public void shouldCreateGETRequestOfTToken() {
        TypeToken<Auth0> typeToken = createTypeToken();
        final ParameterizableRequest<Auth0, Auth0Exception> request = factory.GET(url, client, gson, typeToken, builder);

        assertThat(request, is(notNullValue()));
        assertThat(request, hasHeaders(RequestFactory.getDefaultLocale(), CLIENT_INFO, USER_AGENT));
        assertThat(request, RequestMatcher.hasArguments(url, METHOD_GET, typeToken));
    }

    @Test
    public void shouldGetDefaultLocale() {
        final Locale localeJP = new Locale("ja", "JP");
        Locale.setDefault(localeJP);
        assertThat(RequestFactory.getDefaultLocale(), is("ja_JP"));

        final Locale localeCL = new Locale("es", "CL");
        Locale.setDefault(localeCL);
        assertThat(RequestFactory.getDefaultLocale(), is("es_CL"));
    }

    @Test
    public void shouldAlwaysReturnValidLocale() {
        final Locale locale = new Locale("");
        Locale.setDefault(locale);
        assertThat(RequestFactory.getDefaultLocale(), is("en_US"));
    }

    private <T> TypeToken<T> createTypeToken() {
        return new TypeToken<T>() {
        };
    }

    private RequestFactory createBaseFactory() {
        final MockRequestFactory factory = new MockRequestFactory();
        factory.setClientInfo(CLIENT_INFO);
        factory.setUserAgent(USER_AGENT);
        return factory;
    }

    static class MockRequestFactory extends RequestFactory {

        MockRequest request;
        MockAuthenticationRequest authenticationRequest;

        @Override
        <T, U extends Auth0Exception> ParameterizableRequest<T, U> createSimpleRequest(HttpUrl url, OkHttpClient client, Gson gson, String method, Class<T> clazz, ErrorBuilder<U> errorBuilder) {
            request = new MockRequest<>(url, client, gson, method, clazz, errorBuilder);
            return request;
        }

        @Override
        <T, U extends Auth0Exception> ParameterizableRequest<T, U> createSimpleRequest(HttpUrl url, OkHttpClient client, Gson gson, String method, TypeToken<T> typeToken, ErrorBuilder<U> errorBuilder) {
            request = new MockRequest<>(url, client, gson, method, typeToken, errorBuilder);
            return request;
        }

        @Override
        <T, U extends Auth0Exception> ParameterizableRequest<T, U> createSimpleRequest(HttpUrl url, OkHttpClient client, Gson gson, ErrorBuilder<U> errorBuilder) {
            request = new MockRequest<>(url, client, gson, "POST", errorBuilder);
            return request;
        }

        @Override
        BaseAuthenticationRequest createAuthenticationRequest(HttpUrl url, OkHttpClient client, Gson gson) {
            authenticationRequest = new MockAuthenticationRequest(url, client, gson, "POST");
            return authenticationRequest;
        }

        @Override
        <U extends Auth0Exception> ParameterizableRequest<Void, U> createVoidRequest(HttpUrl url, OkHttpClient client, Gson gson, ErrorBuilder<U> errorBuilder) {
            request = new MockRequest<>(url, client, gson, "POST", errorBuilder);
            return request;
        }
    }
}