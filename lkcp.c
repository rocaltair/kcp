#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <lua.h>
#include <lauxlib.h>
#include "ikcp.h"

/*
 * #define ENABLE_LKCP_DEBUG
 */
#ifdef ENABLE_LKCP_DEBUG
# define DLOG(fmt, ...) fprintf(stderr, "<lkcp>" fmt "\n", ##__VA_ARGS__)
#else
# define DLOG(...)
#endif

#if LUA_VERSION_NUM < 502
# define luaL_newlib(L,l) (lua_newtable(L), luaL_register(L,NULL,l))
# ifndef LUA_RIDX_MAINTHREAD
#  define LUA_RIDX_MAINTHREAD      1
# endif
#endif

#define LIKCP_PEER_NAME "kcp_cls{peer}"
#define LIKCP_PEER_MAP "kcp_map{peer}"
#define LIKCP_OUTPUT_CB "kcp_output_cb{peer}"

#define LUA_BIND_META(L, type_t, ptr, mname) do {                   \
	type_t **my__p = lua_newuserdata(L, sizeof(void *));        \
	*my__p = ptr;                                               \
	luaL_getmetatable(L, mname);                                \
	lua_setmetatable(L, -2);                                    \
} while(0)

#define CHECK_PEER(L, idx)\
	(*(ikcpcb **) luaL_checkudata(L, idx, LIKCP_PEER_NAME))

#define LUA_SETFIELD(L, index, name, var) 	\
	(lua_pushstring(L, name), 		\
	lua_pushnumber(L, var), 		\
	lua_settable(L, index >= 0 ? index : index - 2))

#define LUA_SET_PEER_STATE(L, idx, name, peer)\
	LUA_SETFIELD(L, idx, #name, peer->name)

#define BUFFER_SIZE (8 * 1024)

#define PEER_FIELD_MAP(XX)                                            \
	XX(conv) XX(mtu) XX(mss) XX(state)                            \
	XX(snd_una) XX(snd_nxt) XX(rcv_nxt)                           \
	XX(ts_recent) XX(ts_lastack) XX(ssthresh)                     \
	XX(rx_rttval) XX(rx_srtt) XX(rx_rto) XX(rx_minrto)            \
	XX(snd_wnd) XX(rcv_wnd) XX(rmt_wnd) XX(cwnd) XX(probe)        \
	XX(current) XX(interval) XX(ts_flush) XX(xmit)                \
	XX(nrcv_buf) XX(nsnd_buf)                                     \
	XX(nrcv_que) XX(nsnd_que)                                     \
	XX(nodelay) XX(updated)                                       \
	XX(ts_probe) XX(probe_wait)                                   \
	XX(dead_link) XX(incr)                                        \
	XX(fastresend)                                                \
	XX(nocwnd)                                                    \
	XX(logmask)

#define LIKCP_LOG_MAP(XX)                                 \
	XX(IKCP_LOG_OUTPUT) XX(IKCP_LOG_INPUT)            \
	XX(IKCP_LOG_SEND) XX(IKCP_LOG_RECV)               \
	XX(IKCP_LOG_IN_DATA) XX(IKCP_LOG_IN_ACK)          \
	XX(IKCP_LOG_IN_PROBE) XX(IKCP_LOG_IN_WINS)        \
	XX(IKCP_LOG_OUT_DATA) XX(IKCP_LOG_OUT_ACK)        \
	XX(IKCP_LOG_OUT_PROBE) XX(IKCP_LOG_OUT_WINS)

static lua_State * get_main_state(lua_State *L)
{
	lua_rawgeti(L,  LUA_REGISTRYINDEX, LUA_RIDX_MAINTHREAD);
	lua_State *mL = lua_tothread(L, -1);
	lua_pop(L, 1);
	return mL;
}

static int udp_output(const char *buf, int len, ikcpcb *peer, void *user)
{
	IUINT32 conv = peer->conv;
	lua_State * sL = user;
	/* main State */
	lua_State * L = get_main_state(sL);
	int top;
	int ret = -1;
	assert(L != NULL);
	top = lua_gettop(L);
	lua_getfield(L, LUA_ENVIRONINDEX, LIKCP_PEER_MAP);
	lua_pushnumber(L, conv);
	lua_rawget(L, -2);
	if (lua_type(L, -1) != LUA_TUSERDATA) {
		goto err;
	}
	lua_getfenv(L, -1);
	if (!lua_istable(L, -1)) {
		goto err;
	}
	lua_getfield(L, -1, LIKCP_OUTPUT_CB);
	if (!lua_isfunction(L, -1)) {
		DLOG("output_cb not found")
		goto err;
	}
	lua_pushvalue(L, -3);
	lua_pushlstring(L, buf, len);
	ret = lua_pcall(L, 2, 0, 0);
err:
	lua_settop(L, top);
	return ret;
}

static int lua__new(lua_State *L)
{
	IUINT32 conv = (IUINT32)luaL_checknumber(L, 1);
	luaL_checktype(L, 2, LUA_TFUNCTION);
	ikcpcb *peer = ikcp_create(conv, L);
	peer->output = udp_output;
	LUA_BIND_META(L, ikcpcb, peer, LIKCP_PEER_NAME);
	lua_newtable(L);
	lua_setfenv(L, -2);

	lua_pushvalue(L, 2);
	lua_setfield(L, -2, LIKCP_OUTPUT_CB);

	lua_getfield(L, LUA_ENVIRONINDEX, LIKCP_PEER_MAP);
	lua_pushnumber(L, conv);
	lua_pushvalue(L, -3);
	lua_rawset(L, -3);
	lua_pop(L, 1);

	return 1;
}

static int lua__gc(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	IUINT32 conv = peer->conv;

	lua_getfield(L, LUA_ENVIRONINDEX, LIKCP_PEER_MAP);
	lua_pushnumber(L, conv);
	lua_pushnil(L);
	lua_rawset(L, -3);

	ikcp_release(peer);
	return 0;
}

/* {{ method */
static int lua__recv(lua_State *L)
{
	char buffer[BUFFER_SIZE];
	ikcpcb *peer = CHECK_PEER(L, 1);
	int len = ikcp_recv(peer, buffer, sizeof(buffer));
	if (len >= 0) {
		lua_pushlstring(L, buffer, len);
		return 1;
	}
	lua_pushnil(L);
	lua_pushstring(L, "EAGAIN");
	return 2;
}

static int lua__wndsize(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	/* IKCP_WND_SND = 32 */
	int sndwnd = luaL_optinteger(L, 2, 32);
	/* IKCP_WND_RCV = 32 */
	int rcvwnd = luaL_optinteger(L, 3, 32);
	ikcp_wndsize(peer, sndwnd, rcvwnd);
	return 0;
}

static int lua__nodelay(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	int nodelay = luaL_optinteger(L, 2, 0);
	/* IKCP_INTERVAL = 100 */
	int interval = luaL_optinteger(L, 3, 100);
	int resend = luaL_optinteger(L, 4, 0);
	int nc = luaL_optinteger(L, 5, 0);
	ikcp_nodelay(peer, nodelay, interval, resend, nc);
	return 0;
}

static int lua__send(lua_State *L)
{
	size_t sz;
	ikcpcb *peer = CHECK_PEER(L, 1);
	const char * buffer = luaL_checklstring(L, 2, &sz);
	ikcp_send(peer, buffer, sz);
	return 0;
}

static int lua__setmtu(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	/* IKCP_MTU_DEF = 1400 */
	int mtu = luaL_optinteger(L, 2, 1400);
	ikcp_setmtu(peer, mtu);
	return 0;
}

static int lua__waitsnd(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	int cnt = ikcp_waitsnd(peer);
	lua_pushinteger(L, cnt);
	return 1;
}


static int lua__check(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	IUINT32 current = (IUINT32)luaL_checknumber(L, 2);
	IUINT32 interval = ikcp_check(peer, current);
	lua_pushnumber(L, interval);
	return 1;
}


static int lua__update(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	IUINT32 current = luaL_checknumber(L, 2);
	ikcp_update(peer, current);
	return 0;
}

static int lua__input(lua_State *L)
{
	size_t sz;
	ikcpcb *peer = CHECK_PEER(L, 1);
	const char * buffer = luaL_checklstring(L, 2, &sz);
	ikcp_input(peer, buffer, sz);
	return 0;
}

static int lua__sndbuf_count(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	int cnt = ikcp_sndbuf_count(peer);
	lua_pushinteger(L, cnt);
	return 1;
}

static int lua__rcvbuf_count(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	int cnt = ikcp_rcvbuf_count(peer);
	lua_pushinteger(L, cnt);
	return 1;
}

static int lua__peeksize(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	int sz = ikcp_peeksize(peer);
	lua_pushinteger(L, sz);
	return 1;
}

static int lua__flush(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	ikcp_flush(peer);
	return 0;
}

static int lua__log(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	int mask = luaL_checkinteger(L, 2);
	const char * msg = luaL_checkstring(L, 3);
	ikcp_log(peer, mask, "%s", msg);
	return 0;
}

static int lua__get_state(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	lua_newtable(L);
#define XX(field) LUA_SET_PEER_STATE(L, -1, field, peer);
	PEER_FIELD_MAP(XX)
#undef XX
	return 1;
}

/* }} method */

static int opencls__peer(lua_State *L)
{
	luaL_Reg lmethods[] = {
		{"recv", lua__recv},
		{"send", lua__send},
		{"wndsize", lua__wndsize},
		{"nodelay", lua__nodelay},
		{"update", lua__update},
		{"input", lua__input},
		{"flush", lua__flush},
		{"setmtu", lua__setmtu},
		{"get_state", lua__get_state},
		{"peeksize", lua__peeksize},
		{"sndbuf_count", lua__sndbuf_count},
		{"rcvbuf_count", lua__rcvbuf_count},
		{"check", lua__check},
		{"waitsnd", lua__waitsnd},
		{"log", lua__log},
		{NULL, NULL},
	};
	luaL_newmetatable(L, "peer");
	lua_newtable(L);
	luaL_register(L, NULL, lmethods);
	lua_setfield(L, -2, "__index");
	lua_pushcfunction (L, lua__gc);
	lua_setfield (L, -2, "__gc");
	return 1;
}

static int luac__register_logmask(lua_State *L)
{
	lua_newtable(L);
#define XX(name) LUA_SETFIELD(L, -1, #name, name);
	LIKCP_LOG_MAP(XX)
#undef XX
	return 1;
}

int luaopen_lkcp(lua_State* L)
{
	luaL_Reg lfuncs[] = {
		{"new", lua__new},
		{NULL, NULL},
	};
#if LUA_VERSION_NUM < 502
	/* you should call this in main thread*/
	assert(lua_pushthread(L));
	lua_rawseti(L,  LUA_REGISTRYINDEX, LUA_RIDX_MAINTHREAD);
#endif

	/* to save peer */
	lua_newtable(L);
	lua_setfield(L, LUA_ENVIRONINDEX, LIKCP_PEER_MAP);

	opencls__peer(L);
	luaL_newlib(L, lfuncs);
	luac__register_logmask(L);
	lua_setfield(L, -2, "LogMask");
	return 1;
}
