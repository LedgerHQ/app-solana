import base58
from pathlib import Path

from ragger.firmware import Firmware
from ragger.navigator import NavInsID, NavIns
from ragger.utils import create_currency_config
from ragger.bip import pack_derivation_path

ROOT_SCREENSHOT_PATH = Path(__file__).parent.parent.resolve()

### Some utilities functions for amounts conversions ###

def sol_to_lamports(sol_amount: int) -> int:
    return round(sol_amount * 10**9)


def lamports_to_bytes(lamports: int) -> str:
    hex:str = '{:x}'.format(lamports)
    if (len(hex) % 2 != 0):
        hex = "0" + hex
    return bytes.fromhex(hex)


### Proposed values for fees and amounts ###

AMOUNT          = sol_to_lamports(2.078)
AMOUNT_BYTES    = lamports_to_bytes(AMOUNT)

AMOUNT_2        = sol_to_lamports(101.000001234)
AMOUNT_2_BYTES  = lamports_to_bytes(AMOUNT_2)

FEES            = sol_to_lamports(0.00000564)
FEES_BYTES      = lamports_to_bytes(FEES)


### Proposed foreign and owned addresses ###
# "Foreign" Solana public key (actually the device public key derived on m/44'/501'/11111')
FOREIGN_ADDRESS_STR = "AxmUF3qkdz1zs151Q5WttVMkFpFGQPwghZs4d1mwY55d"
FOREIGN_ADDRESS     = FOREIGN_ADDRESS_STR.encode('utf-8')
FOREIGN_PUBLIC_KEY  = base58.b58decode(FOREIGN_ADDRESS)

# "Foreign" Solana public key (actually the device public key derived on m/44'/501'/11112')
FOREIGN_ADDRESS_2_STR   = "8bjDMujLMttbmkTtoFgfw2sPYchSzzcTCEPGYDaNs3nj"
FOREIGN_ADDRESS_2       = FOREIGN_ADDRESS_2_STR.encode('utf-8')
FOREIGN_PUBLIC_KEY_2    = base58.b58decode(FOREIGN_ADDRESS_2)

# Device Solana public key (derived on m/44'/501'/12345')
OWNED_ADDRESS_STR   = "3GJzvStsiYZonWE7WTsmt1BpWXkfcgWMGinaDwNs9HBc"
OWNED_ADDRESS       = OWNED_ADDRESS_STR.encode('utf-8')
OWNED_PUBLIC_KEY    = base58.b58decode(OWNED_ADDRESS)

JUP_MINT_ADDRESS_STR = "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN"
JUP_MINT_ADDRESS     = JUP_MINT_ADDRESS_STR.encode('utf-8')
JUP_MINT_PUBLIC_KEY  = base58.b58decode(JUP_MINT_ADDRESS_STR)

USDT_MINT_ADDRESS_STR = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
USDT_MINT_ADDRESS     = USDT_MINT_ADDRESS_STR.encode('utf-8')
USDT_MINT_PUBLIC_KEY  = base58.b58decode(USDT_MINT_ADDRESS_STR)

# This token is not hardcoded in the application
GORK_MINT_ADDRESS_STR = "38PgzpJYu2HkiYvV8qePFakB8tuobPdGm2FFEn7Dpump"
GORK_MINT_ADDRESS     = GORK_MINT_ADDRESS_STR.encode('utf-8')
GORK_MINT_PUBLIC_KEY  = base58.b58decode(GORK_MINT_ADDRESS_STR)

### Proposed Solana derivation paths for tests ###

SOL_PACKED_DERIVATION_PATH      = pack_derivation_path("m/44'/501'/12345'")
SOL_PACKED_DERIVATION_PATH_2    = pack_derivation_path("m/44'/501'/0'/0'")


### Package this currency configuration in exchange format ###

SOL_CONF = create_currency_config("SOL", "Solana")


def enable_blind_signing(navigator, firmware, snapshots_name: str):
    if firmware.is_nano:
        nav = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Go to settings
               NavInsID.BOTH_CLICK, # Select blind signing
               NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Enable
               NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK # Back to main menu
              ]
    else:
        nav = [NavInsID.USE_CASE_HOME_SETTINGS,
               NavIns(NavInsID.TOUCH, (348,132)),
               NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
    navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                   snapshots_name,
                                   nav,
                                   screen_change_before_first_instruction=False)

def enable_short_public_key(navigator, device_name: str, snapshots_name: str):
    if device_name.startswith("nano"):
        nav = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Go to settings
               NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Select public key length
               NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # short
               NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK # Back to main menu
              ]
    else:
        nav = [NavInsID.USE_CASE_HOME_SETTINGS,
               NavInsID.USE_CASE_SETTINGS_NEXT,
               NavIns(NavInsID.TOUCH, (348,251)),
               NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
    navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                   snapshots_name,
                                   nav,
                                   screen_change_before_first_instruction=False)

def enable_expert_mode(navigator, firmware, snapshots_name: str):
    if firmware.is_nano:
        nav = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Go to settings
               NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Select Expert mode
               NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # expert
               NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK # Back to main menu
              ]
    elif firmware is Firmware.STAX:
        nav = [NavInsID.USE_CASE_HOME_SETTINGS,
               NavIns(NavInsID.TOUCH, (348,382)),
               NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
    elif firmware is Firmware.FLEX:
        nav = [NavInsID.USE_CASE_HOME_SETTINGS,
               NavIns(NavInsID.TOUCH, (250,430)),
               NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
    navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                   snapshots_name,
                                   nav,
                                   screen_change_before_first_instruction=False)


LONG_VALID_UTF8 = 'PkOPx7dĲoS$fdJՄIܠbAѭ|/.cRm<u6ۙʊWA;ۨ}/o?yA@NޯFjW̵2[ɽ֎Xd71֞tV6}͉FH@,3U:\\̇ړZkѪΏb(mVHHׇހ|Hǈƒ\'0SUqٿ)#)P79SVd>\u05fcI``ŝ*!Nѭmƚ]8Ļ]3rgтRwFRHË[UvKb[܊&Rs%1N˟N֊6l_MX%*ֿst*ic]{Rc`ݑdT!.ƅ)4_ڦZ;%ܐ|>ӟV1ʵҴi>FU"\\װ@KPԖ<=-~ΦZEζ1ϥd-!8Sj4P,FA7Se"BK4y?܀w=V%AٰɩBʩ5OWΊLiz"5HɚױؙVy^սhJU|&;:e\'`e[26Zdh6Wاj]kCZ|ѿIĚDE"3iQKu.n[Ĺl0_&ԏf:i~\\^5Աb@z#A7>Ztf8Ԯޅs[&zѢ/y\'uS(VS߉!J$<#}+(Бs6kMwY;ܜgvJс!ʌ$q\u05caPjJuŗafx&mxy12=0~(#IKkF:4$jKϤTQ͙\\ՖSRJdfDs1qa3`3P?p+8 R40ӀF,η%͝{0V˜֜W&e`GN[.f1wBK\u074bYOJG^ˇ0ԓ\\&0=,ܴ Ѡmՙ9\u058cڮm+yuqɅI7\\aoK֢H*s<YhЎ~5ФFm0Q:?=?Ƨw^mȏ9Ƙޥ-=:D8V,v-˷~;%{~|zq(ocRRܶԟ23֞nYW?Hj2e6cޫe/cl~%!WEWՐpg_jޒV˲J|,ԓs=D6ǚĔ;0Csj]w߳kcőL43ݑr,ϫպ=y0=+A-Br#=[iȊݾbV.w*ȅ<vLfɔ78ínvWU\u07fcS,H˺ZVwFnԼ˭Z_nx߄o):;9L3ߡYbե*Sʀi+p}7l$!ǽ6{ָGC*Fa;ĢB [(aT\\m`$&Pqe=Qʟ܍\'XPȚ@4!ŻUfuay"L=YKν3S#`%hx4yCZJY\'Kvga|\'/ի}_g-zƍ0C;VTxgo?fϕѣ=ts:^oŗʹθq[s81U"D7kʳ ?yU \u05fb&5ӂv8V}ߺr4cDdۯ"R5[Ӈto-fO÷ӳpܥRVCƹX҇УҡΪVߙiCb7ەxr,ϘLƊKiGy@e/g:&ޔnK[y`qMs3\' <S+H`کѳI>ٺ("Tred̮ax-Q=P>`N]qLg?O֪ĞDKZJֶgwҦɹT>qX fݏj`gȗc,8>D5VjГÌլ%zL\\{k̶pLsn$I%ʃXY{[)B2Y"]ȃ2Ȱ:~|K_m]ãԵa5Hħz!yN;*ܫك`ЯmRҰBwhFDڀV?SÄri\\z(]ì=ۮpIc{t͍1Ia,أIpRqLi]d֧Yp9?PRbq>\xad2rM)ȠUʹ(fN%םrؓ@wqQπ-!~1нv گ:xǌ$}>ԛulwŲaZeSϰO\u07bcsÆF˩N4;OC>yvi§(]ffJJXd0݉ȵ6Cv-tϧN o[gP#Xh-bݠgh\u05ebo.:&Yjd-oڛ{KYץ2<b\\ҝȓA?mBa¸a2%CdANԇ(Ȅ]tin,=DV7+ZBڮԜ<t7ӆO)I6<̥glI6Ɓc/G:^ĵyف\u07ba9Lƿ_7D6̦u#lKӾGǺ)Oz-֕LA<ϓ (\\ƦЇl״Q<״EjcUJ{QLaz[Ԣ9Sٱ̬i_Tdfpw§ȿڐ+Y$hF3;ڞ^IȴWWLȃSֳ!.HЗ"j y@ĩm\\!9QQJJrA<uO"gYD`pϸPD;wbcv0ȆnvP>X{ݎko&SÅbμc5q;dogߙUUMfg$ՙƵ8zr3uݦG̱ԱKڃ9]\\пhhGTUx<|1~βLmy(K؟(ÁqT:ɓʸzcmzDi:ךp2Q+ōLfqvӬ3ڔȗ[Io\\ln##-FgבFFa6.*"7ezQXJSvۈ)Ԡp֤Oq}QlBv|s<7;qD>&tƬ݊-Gй߰w/5юt)\u06ddq-9faϱ#v7T>5ej΄#f&554HZe?TeͤOŁСu&BT/VNɝ͐9=)Sʆer0b3zuȱQ7m5yEŅЭlj&xwWFӓ,dGYd),ܗ=KS*ڞKQԳΑ%>آ\'jOqȎfe@ZN?0ˋOMaآTϝZظIܿ5ZѿGΦ\\_%>]1XAM}͌TơӬТנX׆X<\\T~Թ\u05c9itsy?I%WnVYqQO]Xźܙڟ!çԗH<9] ̋fp͘\\-aj.9c&.nQ%C5bE:1ƌÀƉC$HH1bHK&m6 Ë"HB!:?4L_CwAWALˍ.E˯osۣY79_5Wd1$Awع%ӃhȓaLs0<LVIѵLUipHםbIJɪasE?`p0WN{ɬkT܈ڐл9ƵXĩ}d1ɑGɗ@rQ&&[@ѡΌƟxJrV ~y֙}Qػ;m& 1+}JMٰNU:ֈ\u05ffd/*$GTruٝ(c̵̿\\k@)OVu[8mOKt4֏Y7t*È9}/ٗȮPlIʳ:/Ͱa5ŧüKd%:-@<M)eJ2P,X#(#M\')է(98D<?ߧ9DՋOƆo$WXP_S3=VN>Qfrvf;-ŊͲ0BEQ%0(qh]"#"Z]pAҪZF9ȃ؊LVlɽ.jc ?\'xWɅ\\" w^Bώ͔RSʧǬ[|S٫̕ݖ-,}ֲ}֕m74R?m>>kGֱW:КnQF24ƦvUm,8˔_ا)hؿ*tahkו66͵ܢ٘ܲŢ)U(*A̶(ѬofVhЪ:eJ+pdO<p_̢AEUw\\7q%216O¾˱+s؇*;4*:.s$v§t4719Ue5Ť4ϰ#=՜ѹiGj? ZkՔx@#Aۣhd}L/ŝ՚o(҈\' )ki2MƢЋD~#¸rِĖ[w̑L=|I:q/0+iʎgjſжvofLvBٲUrv\\G=^QܙY%*ƳՆ4Wْ7O&I¬//Q+@&Qۊ<ZaǼ\u07fbL/hɼ>3ƅaOp[(Ug9>2VxE(7TEعj?k1̻o$o@d8_e\\:s")={~=P؟j@jǔ$#%TѥR1ԔƑ;&OsS(pڞ@{Fy%fod\u07fcɆg9A8ME1۾ųũ3X2ky+V?tW/7*yrι6Uм͑S8yblΉ֞ݔYo)@[F5YT>nB/PqoZς¿tۤ۹r}>f*218K-vǅZ==Pzи\\دDʑ˫юG>ܬooX<`,.0ے{SZfĐҡBWeh#~Ǘ;ltks0mR_-a"/C%s#-sĄd,=t=!7PCؠmǫ\'-k<הļ!O244s2ٽ/kN".3)܃ G#VDg!ŉđ,Y~JbևՠHŎǭYJ%l\\li۬qgjw\u05c9|>˩]ȅ|אGMD`ponIG^95%eb-Ek:{9a@߾ڰ<7ׁ [\\ȝLҽFܸ4hFڤ*S\\>dy[ìJ4#$Nv}+XLѶł=ݕл^ 6N͟9gZ~LZ#"@)Ļ8נe7CsF!\'>!]Y0qyu~gٛÁVdl5ܻlٮLNeΈ͘7rϮ&g4Rl0|[/m5 2oω;LLI#db\'>R֦#:{ʨ-ލ/PI?(ԮJ:Ӯt{~q@>&Whѩ-#V;M~x՞IP(%3Y?p{4(}b_ցɋ|ؒ-GV̮̿jx{۱0R8r"RjxmZ̶Lx.Jg\'tĪ#aS}6Bؽq eQ`O_r+M)n>dԀĽj~͝gw7=CqolÉ&G֚X`he5Ų(6\u070e<e,(}ܜú!SӊNJKm\'|~d\'p$$J0!W.̺\\>hL~k̃J5)Wj\u05ec8siǋ:SǕӗ`՚(ҫdO&]ϠuԳ|o\u07be\'ǪǂU%͈kx,V(ZmβʣUcU:,XIBMGfMќ{^iŤv}<{6X\'NJˬ<,%\\aLǀIfXKӄoXc]ۡJ{\u074b$ȑ&ɜ=SuÅ\'[ɉҞp\u07b6a5O^g4zJҢ=rZߊpNp,ޔŴ;ģO&4CmurNs?8qZ"[!Tx4#\u07fczёPld :v܁zn[B&_2Ͻ@!k*;ä/2ɦ\'DQSӓt)æ2V^uܡ(ݢ\\z{:\\ȴ"Yɓsj[ޛ1!,=XХoŚkҊs3ŠĔLV;ΐWGqdwo?ׂ3Bq.,p*ڸrGE~ƹ>OU"PKk58MI)V8fkSh{PvouŸ+ixHx¥^,oEɭZOۏp6"Hy(t0Q\'ܸ:xҏn]qp*ڔjǌUI]FTb6)6}$+e8JIr7B,"ю_6ף(2FP=RF@Jн5"lHťRVȁɈ5.ǭǢߊJAX:Ҍǒ)¥߫3ȷ@N_$»ns"FsQ4]ȐǖcF\'*$<nɞB\u07bf1^-#~9ՆpQHSUP6dJ/B{_1"h#_}c\'mЦ5IwzD}\'Ings8ͪeݿC7b\\M7ڥTAEHG҄~˭8Bya*.\\è<(P=e>zVSHKʶ~iȐN!;uhhmVʐ[I\u05f86ĠҨ8#=Ӟ 8ߑ.̖$F\u03a2xAcޡ\u05canZϿWPG$vY}tO=t5}P֜Ҍ6mݑϑٻ[JVI*jxʔM[Dt=:Bo6xt.ިĩޣʰ.8`0EkW|jڒ\u05c9,T|bCawޞ9/D2|^thӒG3dq${ZCf?ߣXc2ޭυPvܖTȾ2е٢gHQ՝U۹Ͽ\'u(O٧ۭƲ[CY7_9\\U8¿ԋtւ1ڲ`GėȄX[AϪ/_d&0%3ФvK!I:A.g/[SDg´z-5ntBtѺN0̺MkI9g",=Bۏ+нηQkcjDȝ/ԲwslIO)5~-%ͅjQˋ8$PyӐ֙G͠z>åYԗ{øbх*ͮZX 3+U֡+Ԃ\\\u07bcY[+!aٱ,J;EC6(-QTAۓsJ$,jݟzw:+3*߀Ү!¥*\u074cёeNNq@C3AeqvΕ)ʶnЮ!^>2)^ (Rj?!Q?%"WӉʼ1,ɊIC4ڜ{!$6 zx~H-pkp-QM:z,˂ג]MB\'1mH4[HNȵw ̐/j-N2ի.(}h_Ξ%ڕgsd*Vx lƯ5ĨA߅9ppӿv(GR|WQ]-[fjD֘*Ɓ!((1šgGLӟ\\=OuSRǱ]۵n![.ś(˖Yĕr(G\'űAK+ůV8ڳ֑Uj)˽FNw|g*¹ShxȲkߌ; :A|lI=qѯP,O.Ջܸ݁"&b7teץkB4݀ۀLɃĦwWϮ0E4^T+v4Fɦ5\u038d|~:߉mÒ8TaǱH0 Br/:6a?ˣaʠNA \\*~2%w^9o!ݢǞٍ7(Z\u0603)i3UZԗXqlԵ:@/ÇTZMLHpaݾwa1?`t^RD(̧}щK%o/p}X 0#.b)GUi0Zwt`6uF2Deȣ%̀qWfRa<C2cm3@i2EW0r܌Fy=I7ʯsĥ]w^ɵʔ18_ѭӼ5NSݓ\u05edNqgyEJ47QvظcK{-?(k4"^Ӈݟs0?aLpnO+;N\u074b28Lѿ9^ޯ2IV(9OzYѰ&jrT/>՟.E؏xƋ@ڏ%#cR˯`@SGS)GPpsU4\\Lq2L?_Ġƶ[;`]eͷO[(m.qC>`ߒɢj)Ń{ީhk՝V\\m؋,đK&3f3*ܐQ4c>*ikfaciϞkvхEcÂ+r6P!Nلe](D?[(ǋٱٳVݹxJ̕(P(}[q2ԛ#Fŵ7ѶGi,b(ӉKRy :!ſx\'n#VcCè*2Yԫz?z=ْHɤia۳\u0590ϩѿASߗ|GFZ~ϵag2*S/?1fkX3xETaٗ&PΓϷŊZMMĊ˅˻ؿMx<ȭQ5YXhܛerʊĺ,,xV5ޡ(([<d,՚őˍ¼UJڢ8Gs@ٳٻϱ|}Zp̘45ӈtXknKԚhHb.<δޏqX`ToYjjH$yWZi,t˯6_ԱFoU§.Ó04=ԺҦ>hݏů:@f|JM6s;ƞC5!0;x9&5f2U4UR=9р@?²lTmuYXĢ%m>N&ًҏO۷coXUJgiYLnHa:KVrn`YSɃ.aDqĳ\'33`20zӥ?{Q<SEψT;ƫ֕ۥTx/ݓE`Ɵ`WFuםAڑ|2Xw^9! \'}Iȝ_>4eք:w_dW-\\ӷiz4L4ѡԵR5ɿ°Pno2!2LDs π(Q҉ǋeUIs(T s$K{}Ví7NWtRعCʦ,=Ց4uhnrǲ\'W+>9ŽKȣȎI=/4ǅ2߁y8\'V<DlМW[R(ɡ\'ĕXLgީc}xظRwIV5lt/FӒH~t̏`$ĵ\'x aȣWvwݗT܇pY\\\'d5p·p9]ͷaҸF&S wI]eŢVHTWdXYƤ\\AЊkǽqσݢb,PwIPyķҎjĲX52}\\^ӧCFYRJ%4V`@ܷU(J]KX:X[yw)o%*NUwa"Q:)8ɬKQAC%zO°aDtMƋ} Y>BoC8;{c̻u0\u0605)ٱ?HB6s6_S,`7G2Ԡ!#R8i0+6\\*C]F\'!9xx0\\jɂS|G~:#nHĶ,%Ҷآ!ߤ6rTRî%ЫP(#ϲ]Q{WBgFȪd)CM;ûfF1-ԎӖѵ{7Ɋ8tWҧցժ$Q>̯œEy.6WI ذSMu`ǣ6qOr5;&j`z,"!Kn"ăI&)N/)˖q0vGICՉȌhOZu6.̄}Ii̳<@Տ~XBcĤ\'ןǑ@(idѰ+vH{:+}_$vjil&D۠za OӸ`}gWF{Rܑp_<_AԼ]ظ؏Ainš$pS`>ْ\u05c8L~MΎƘвk3ϏG[Nś10pXIw0];ܛaіm"hS3ts5(ӽ ڰ\'--;%jcϞtO]۞Tdɨ#*ݰ/jj]D֯{CzrkݹIT< MAHaƯVSbp,,6$iׯE>9%_g(ݲ1G((^-#ҪNf\'<ѕ*@ښŮFЦ178s-OVڊ9qDG-Ǒ@֮n\\pŞ[ȻX%ԹCŗſ¦t3zٝg-8md&L^Zp,b}(]8ֿ\u07bb9°@dvGރȰ܄ҪMӴz88ܸN(SPMyPLUAkh)"WC5eyۯNRsdkx̢9B*AkďAëf?1NjsQ(x\\b?pIP2Dդϲ̈XȜ2ދJzXʡՅJ͑r7vX%ʳڎTB!=;.<.EP(L9;ӣɨjیΩw!(a1|(1./\\ßgFOޑ [K%ͷ]ڻDDm+iIu̸6WO?J\\nŌ~܌K *pΒB9X.ɘKq?dbׯ>=VX6kN5t3lnGي!ޓˡ`ۆ0yr]͌\u05cdԜ=IX/V-:"Hw+ָ9\\ٚeIs{pu8Z/ʶVӫw>(<$cKVc?wҢVJ*DѨϴrzVҔϦ\'pNn(]<g~9?&EvRh[s\'ڼրZZ=ǜMV)أhx)ïAeЄՉ=hpBa*Y"eC٤~eaQ\\,͔GԷSZ۱HyHE?ԭ,SSɍNNh}\'&`;¥-~8j{0cyB)լ\u0600M;,kaCW6CBO8ނ[oΠߩÊڡIYgjһǼMʎ\u0602tV!êJF/6%A=/[iC\'d6]MDg32[CEY.`.sI̼Ø,НʘRڡmyJ@vGԢ&҅WM\u0600@QZMC5EYO%եCg[ߚַk\'SW^j"ynˆxվA=&iػ@>ߔُF7^Ot©ػMψsM9ܴEGv܉5>YwcچxlP=W2`ߌŸh*ͬҊYxZd۬i5/qSFRO*_&Տ/<M1#4j(r4|OIbx\\Zrռ=zi?GkClE)4س+Uaݱ/(Gٻ\u07b9Z\u07bdvV(GC3͙fP(vձ~Y?tHRf.TyΪ)b֮ƃ_+:=;3ڸ,{,;yyܽapδ&>2wnDޏ\u0380pc!°JU&:;yLO /HqKȜ7(wߢg/tqGeGĠ4G$dGFk3>J$VD)>s_ϣS*@.:u`9ʼ-ЭŰdƚߔΫ)|̗gqw1\'0҂@Ę,}e\\^)^?3Bޤ¼ت#k7vEF8xMNr"kCOzӸ>~eVrzɏ/Y{݉וGy/Y}0u*\'SޘaR8ؘKO!{mɃSTLP,7kiښyáiw+ jtK\u07bcazmҘû^4Rh4,\\(Cź ɓ͐[~ҊԾ`OM( dяJwiO2ۣxЭ/d8l.E`~cј?ĀU\'Us[_Lsϒ\u05cftZ-fq{ſoX-ոωXcK0BGΰWX[ܨCO#1jQΖ\'?ƑGԞ֣Qpq5m^&$kkΦ>=ҵ2N#Бn4j[D[4gP-ʝJӏ!Jڞ{/gh~B_vD]tY͚[E1Շv؇/TozP2JFҵ7;\u07b5-\'&aŸ0\u0382+s˷ƥh+0e֜{7YoU?Gp?<,Yl(ςI.El\\[ǋ4~;te7Jsr/nתGde f43ŠE.y4O[ŢЬzZļHɵ#с3ε]\'Qwp!t]]*˓٠6hԛ?.tUxJȪl&MĪTd&w*ȔmP>2ٚēʚz5/ی|a4̈:}ݸ&rTdu ,eܦ)iޞKӉO%mRfȿڸZ7Il5`ŬTm 4N^^!ՠо%۱ݙkϮc[7?_Nsσ]pLw_4c"gʻCŪӫqɻGŝQNÃr<3REn\u061c>~RDXY̟E+F?ogUOWFk2K|rZ&*T@þ99G)v^ؤzr2-,0{w7l>ߕŕc9̃շօ%Ȍ٤\'xWluʉބx*5-nȎڟ4rN{߈a,^]1Lѩ3~`i4_؏q\\#4@L9x8Y&kn^8P1HlјPM؋QS/MDmrGֻv.%*t>TsȂV!>ڿ\'b5X`=;fѹۑϒ]͂i(G/fy`vը2Ulunlg>ҳgaH7N4HbޕH^lu1\u0600fĪH["8Nүhhd9*#Š%:nZʦk_\\˘&̤_F\'f\\2&`)ԛLАp]ۀ*W0ޗe#N\\*ǩf8<,R),mDs\u058c02fүԻ()P|\u0558N5Xʤ/҃\u07b9GPwiȦWL>HݡPJ~<oͣW&TMΐz+,[r߱ڿ,g\u07b7+(i)i*qE;߄2֒94ēĖ:o;<Vd}(ZǸjT5ܸG_VaH0;7d׃|=c+c.\u07bc=TK};k#Ǟ<5%Ӆg[e϶ZPo}!bA&ڨRjkܿ(|̱s9 bYlsiz_15>%@5KJVwP̸43}1Nuޮ˵=;Bg͢s7JٙrXXza-EpלcpD̮֊Wd8Ƕ|h\'[]tkm~Vn-eHau,ޕI2goE++Z?ި)2`׆RT2_GK0o~NqaZ1Pī\u05eeȍĳOԗEF~3ܝvnx-#eJCYҀOv@[E͟w$àX<I~ƍ~+ msjV/[0l\u05ed? VـhzΡZzBMHJRl|bܲdxпڒd=\'lWے_\\DmuϜA>n-#κ0~NE)i0ơݜRa/æϠ!/Gӊ(JK̥#ǘjAЊD߳3a\\|\'ܡC8IӒ8wR6v0~Ң]bʑ<\\Jz-U>qnm=I4PGlrjUCjE%(iBsdҷu?@/sPjɤ}hTƧw҄.P4p^ϡYS"Mj{Yٜ̣MB-_`RnyzѪ[ 8WޥE\'ޤR&1%>ĦDNώӼQرR~v{m.Ǔșwb\\[-؉qo:Э\\`ΏQ-4|d\'Ү&$ش6xܨdƛ5uǷj5+LȒZ}:{NIʥ:ƎmO٘|5@ҩ[l@bEvQҎgȍs.=A݃Zqt\'+tD9/$2J\'^O#y<t12u496\'z#˙M}qfs?&ǃſп,ٜؤIx_W̏VA6+ܭmNlZǯ$kj[_4o"uWi}{{־"Sjp9V{Z̭BmNllM$ЊϝjUC*;^\'ϛKڪƏߙz(*m|NCCѷC0^.@vY)͏Gn8u[%\\M@(+Tؗ<DPuIԱ֞1ۉ}cț*rOq,!4О3qS^iMɕ9si|,9&}VXdGUyQ\u074cujcɝ}Jׂxb?O|ӕ}>TOiHβANG*̝ψzʃ]FWV|m1rU?ϣ"c*Q\\Uuݝdӛ<SZcxAӾ?a1(_ٌ;7aʣs;geئޞ9vd|R5zU%$>ǷƗ=&v1.b^S̟^ۯW_Zաm&nRӣvˌj<m(*,a:Z/xܛMɖ7mF#R$Zb/fݞ]y~Ya70z|\\j@x)?]Bߵ̇О`5ߪ~# ]߹ފm3%ċֆ%Gaajɖ@W"!Hێ(i.~/Xc /8ɾwl]oPbIճ).UOuJR|!b˒/oĜŕzļ,,ϩB̩<ģ$%e*̬Р>ɚ@6#F=χ@mHsz|{âۯ\'UGWsQ}~kȖ+o<\\͵ӑCr<p/Ϳ҆<=vgo;ޞؤ[|=G5K0Yy#VIǎęԪQˢ`Hb_zѫCKzWٶܞ{BRD|g`s54oC\u07fbwԈl3Ģ0;T0)R8פTtCR,סښվS-ǡ_6Žgٿ1T5JÇ۶di-~bȑVwt@/EN1dB(;Vʯ`ԩc~ݧ?f%Uպh.7ɋqЌGoʋ5f!ߏ@3I+@wTԭU& $рyfh٠Oͼ^1;d3rAvxɌD!CΠ+Ӫ1v8!ٞ.bBNےҋ\u0382Z~lZۭWyAv;M@cػxo>\\Х٫km!mbIɴ}ȇlW|3mԶޤUЙE}BJ)OKb\'r>tǤyVۺ6VvlG4\\{ik\u05cb&֮qbZ$ZYqP+0}MKbBաCj\\ƳE=װ_ Yʧ:jn#-][ԁ"ӊ[D@,S&{#MXܣՌ"rTWwʪ\'DT6n)Nk*0q?B:mп;gПUV2ZǠ*\'<WF"5И ԡj=UȭUY5X]}ޯӂԿހa]w%+]^?&?(-1)PU@Ǣì-{O$HmX4Ƕ<zpХR"97oل݅sMK<S 9M"{g݉UQ+AQ߂R.m$-c+ϱ^R00gv0ɋ:G av!Ռ%"37=~ܳF#Ҟ<l;ϋ~~U6є\'_=Ф>jKZ7o{שƍͅ:m^٦@F|߿ίگǥr~Eexkǅp 5qDڠXė˹&oiܛ;P7lA8>ȽQoΤf;"%<ܡўaK!M¯)C{Կh݈V_ %j݉KH\'[h1y˿NDi9"^vq{ğNdxmt#9;CgJǴ&g$RƑk@ԣRܖІ/8>;gΪٖAY;</gY[1o.ma$C֭!*j^ǒЇБHKȋ^\u07b7]bۼ$!`E?+rߗa ga=,$Ѿec\\jO;mN%zTɅiPXŵV_:סObQɂ˾ހDB\\Ǵǩ ߲ٸͲ¡$9ˉܒbJδ-#6ȭͿ8ŉln[th_8.z[MIwBľO7Ø^\'IQ[Yߗ=ItJ\'{7klҖcv=A!ѨsƗJ73.hǠLT5/F7Q.RփTT<ϖ߸eWssB9QT&7j\\Xb^AuTŷߧHh/wPloD&ݴݿAaSޢ._qQ3MBfzHFi+*âԬAg[#ŜڪÙ ʼC,7Ӎ#6&ҧ@"QNބەdΈDQlH>G^O76ߛMnmź9];#K_͙SzYٹ!q,ߟיrz=r#ru?}wj%*{ņЙ˖~BʹLͻt1Ir͎ڷǛpǏMPGܯ.cɽ^W(_F"iA1LҮɁէwOŪۓѫܵwD"`3HGNy?fLۑ<6SнXP{[[$1dcӛoc̣5Xv*?тHliש)ܹe][c\u038b֏p/n@4Ֆ7jˈ&+Њe=\'1nW\'x<ițȡL;Z`eDf_/.?B&;>ͯAU)+QĭWۻ`@Nܣ4p8+eޜbɛ(ь20`cԖAa8eЍL}aɁ6f/g=Chpg*ޖT"=*xÞָN:L1lfTč\\бGsc˿+g8AݙBNïwE@h~ ИF{w˫n#>knubGdAțYtעU˛F9ujmՕL݊fH+ߧ3%RJ:Wڥצl$putآRܱѼKeƉ;B؞Vѝ30qy_P!\u05f8ӓcz۪4ߍ<ҡ+#,ާ11GͨQ~umH~#Xtȇ42X*ՅTvgY9{!tM=ݘXwɒ\'$V\\r6Qh>QIS5ܚ"_mȒYcfٞwwvSuC?:QTj|TןPm(xسlnqϳrԝa&v2>(z?ݺ^7o˻ήGVHti6Xړph!p) }!Aۊ]ٶ&%>1/94ͤ̏MD$7N35JɗUp?ƛ-ď??BE`-CBڏɍyZ=Gfkͪ_ ӷ/qUnκ4g73ӭ؟PdeoeQ֩P6JAVdEFՉGSޝU_y0K\\j7EnO&6M\'B$-Pɢ(֑"/6vI H[ҳnɹWöGƛg<ـ7Hyu͎j۔-˸لS3ʪW܈m( 7H@i[m~Logؗfsε,"Ǎߙ*\\,W\\Æɑʧps:n;%bu}dˮo+R!R6\\7ǖ8?čaǴ٥ڢOe^,:HŮƳ]ȠeFgVzEv[7ftAd0יPc|z#Hdʰ\u074cmۨ<x`KW\'ͦSiũݬ9$2(K7Iޥ)v.Nٍ`&יGزB[Ւ)]0|P-Xͽ\\$lYŃ-Aڬ.<4تNQ0CϟDՋƭLói+|ʤclm,+5\\Įn8<̯ζjq˫7dB@?Ƈ@lG*#=[/ř{{rԤPfƔJ|V^x%њƛMq/յRaRxpܘzlFܴ\'yߺ%Yre=ғ?k)Jџtڞr#y1[F.3ܼcT|o @.M&ǧήBբJ"#] ơ[KV0*#ҪIU.O~=#ui211vh#Fa0i/ΔP,(Bp=GRZuy*Zfع\'&;vr!ҞJ*)3H9?rʮӎ>@^Lj% R8(Om8Ƙ"LӘl3Myq*R},zךW4?(މϓ}I\\,Xϕ:úXvQUbf" ߮(\'R:*λVo%)آe5dɋ*վRFy9xIvŜϩmL[Ο.x;Ze?yPIF|,DHKٺ\'DfA3}^\u05eeƉQ{2xK?ʆۯb݉%w7QA̎]ʦH2>ǃ_0W(_*ډ;EȨ?Q<j"9їȧGco͍"<s~2Syie̪HSbǲE`AAn¨Qcɛ;w{ݴMLYۏΘޡwܽ4Ѷeiש+ 1Z`Wx>.^CʠؕOˀ̠I-WD{UƬїBd֎A!Gօ0S΅NwF8jn͙_ބZȮXsl9V8I2ފfӭN"JWޜԦ;mtT2.ۻ߹ȱ=~=)jOϠpO\'٣N>ώam#PPFrS*HΗp6KZ8_EF<RD9,ؑͨQ1r^.U!ã}B C7ҿܶζzжϮD*Z-Ћ%>¼*ynܥO e{\'l_4;tHǖOɫ,U-J۞D%N%oΌ#cȠĥ\u07bdgkΛ;pߨg4U7/ėBOL* T9F?[.}Z.XZ=ϋȑq|Νk2){;^4KCСo/W"w-LxەɷD\u0600:\u03799;Sٸ,j!Șn|I;ϓ|m4ɨ!t±hYkޝqMNEZ}\'G7o,ͫ]đϢF*@55@;x~ۺͭiđ73dPgB;V"2ě148@9KMu{%b9pۘɢ[O/r}|9\u05cdn4J\'F\u074bfo{#ŘLe\\2Ȇ:Uּmy,xٵMמ3jċNXpyAiDzh]0iyL}Qˠ\\}P>SZG³;:,~uI̬vωkmgHCڲ#ڨe8;y}TYvĆ#ʒiZyKS+ȧ¿ٶVUZ[U֤[N8YȮ{8F%M`ؾ:#k=\'(zm\\Ϩ _֨˰׃A~gRȽԃ/>Mxgmp٥߉ڼۛ%[sIիԃn2z<Ǣ#0O˔3sƸ^eQӚ"&7acՐ~c!4`{>wT<ߎ4)>o+cփbͺ]Rw1n<dm]mY.܍p0ۖ<!ʍF(Cۡ.OڄTu݄$.Oóz̝ݮ<ܛȢ>)IM9_MЬ\u07b2Wg<J:0,?kbˏ~l1sՐ1`~ʎ8Y͗/lT"Θa$hl9È%JtJkTȡaQx^"Dk@Y>X,<>sX5`Ҭq+vǯzޜ*o(/<rpռOYqɳM/S_?g4EUĖk,mڕPk#vAݏ>NϧXf_ynNAZo=()aٳaT~[UڑydP39bnecg$#،;śa8فkݽtR2ׯϭvÍވ?Ū}A\'#V7)֘ݝ˻ottԓv3npq`Ϯeϫ59CbJ6˺L`"щfufN#-[4sRaհk΅)7;9r.F,-VcVRJ(9fG-r\'OuZ̭GҁQBH<\xa0m̱hQ\u074cx3$ӅMHF?aN6\\9tʄ5m9o{e[Ӽ"7!|V*3*̾0c(X`CWŴԒ\\BfWdʲV%hņK#@^ªۜ=ўoD}WF&&V!N[g ̕hlŗaA>UaY0wETIbSe^ʞק>|hhLLdX&ѢBFpwܟҿ3κ`N$-i>9ۑU6A;>1GCʶ{VmhPް4 ?\'?2I\\:hXvӠ;.r\\]r6f__8/gI1&0\'%3P#JzԢS>Ë`F5l[qON0щ.0fNw?Ѱ@hVޗ8\'}[:#͒(uOaBmv%f\u058ckUדBxyV>{VӠ5BڹD$E aܾӨ/.~H6}V;?f}ŗ6[ΚTTi~L\\zBr9axϛ55"|>cc~dd7ڷ,۾Rv4q)u6&c.JȉҢ-Jy+Iș+ϤS;v(0$YتMݐ͑V)y^\\ݶ?8҉+2.$sh{cj}1f^GbՐc\u0379=rNsVbvή̦|\\ǟx-xôAͳ?T kP6*[jRJKq,v5[@z1p6")UC21i١7w}I۽uށ3[3!ǯ&jIf=SdQP\'N4ݽ/5\'~w3̔&V1t1ͶIcحQͮIpa,0YwbS˓0֜NEȈ&{7ռdUp_pboǎveCFGǗԱ%ˆTٚΠKrȴ9óoޓ7Dϣ~ߵBΏ2WMNOd٥NhC%xx#͈+W_- z֙V`Z[^St{d8g]ÚC3AO}Қ;585TlYGjCWĜUKyo"aiӲ+_lٱNxޝ\'ݙ\\tw)FVZ.c.2i\u07b33TSO4oGIͷmΛyI[^/nѾ~QtH-bah`eʨj&iEvEh͂C8к\u05cb=F/1@?N\\4P,ЙBHdV2QR^wH\'N߲ϓʘԴ҈]ف$n9j:"UόV]-Xldu%Ѡ0V¬۰ƕ)_Ŵ)čnѼâՔríHMܩgԯF&!܀Tb(d[ۘ"pyܚ0;jg\\d7ˮG*qyI/$IDVXVAߒ%L>ԌԽ@ͳ$v_LVuX~_˨1ϫ.^КFطm!qօЄO[sHFݗX?);wN#֕ՅkCݕ`ߟ!i_%Ha4aZֆl_ۆȄmf!ŨA}؍÷ƩQzәIg)9aޏ#NyܕNr,\'xZ2:T&iU _f/N@8Ep;7lAٝk:AuɰWXQۢү<AţBQO[Hceĕ֣ύ[dBܝ,<8ҊsrWu˞/(H`#ɤ"BEu+#r;/|y4R-~pЄztՁ:Z!˞ykHR9}2-H<"נEρӒ}a[%ʉ;\u0600Ĺ5$<XeÙh&bג6͓*6`Ŵa`1}nsd8E{B%Eзx/ѕ)fҷԿ!O̕v^+|LXTiь3{%dYėi DՠZB$ջԃ9@"gϹb.Vð0)k̛Ѱó=^|VzZضّj\',ŞޙH,Ohi&4w"ӆB-y?Iߢ|)_̚ЄU]͊\':~J\\]$B®{bIъjYMKY/dҝ((}/pfҊb<ۻ>ɵ.(Ͷim#ъ6<bŵtCƖs!ڽ\u03a2Ă}nGm9\'hVGNhdZӇ$v}T(!םK؝R&*#N{ć<x=?K;T>0`ʊB#%ݯ3X݂_tf#IIA4}{dNws]qh`"w3Aφ4GðA;ZhÍ@ѝ7\\5+=Pٚ\'z5jTI\\dI"#Ve2x;5U\'[A<eoxsڟ@טOÕ)۸Xߢʀ8ʈWb\u070e\'bwg lʾوbcbΨ6>Wcx%ۙ{ӺX˛/&3v ۋЀ?q;DFm%Д҇8-P{˺,[Y\\Җӝ|ln{$֔Ⱥ_pD&j4D4+n|g:j3}Ce˷Rt.ޯ:r#"Ϊ=8?1x1%=ݎά-:1ߵ[^wuvǝ"&_%ŉ^V۸P)Lϟ\\֣Q>Yջo\\QHǃ0ք13+ڞH@a><jDS~FZG`Ri|ZkzbڡDv.{aԜبoʒŀF٥=ͬԄCT!XK04V&iȞyWt-B˪^E{˟# ҭӃg7%.ֈb5-ڲu`]ǋ|Ns>xAttU0υ^RA0lߺb~ѣǂ˵͔a@sVBʏ+DnA:ɘ-nIBrރÉ۩P[q+jAGy}0m^"C43_y@>;qϨqPBЀU>qL.xjř`ִ"d&BڗT}O93UR`˹b4T\\5Ϯul3#͜Ǥz{1|ӣeo`c٦XJ2Jo͋p`t9CM"n@_kCȕ٠ǟ3˾pײ8/|/-MT9ɓyGX&\u07b6Y`˰)pHdv>,:a˪8E,ҶQP[A{F\u05f69o\'j ڨM9@-Џ\'H("|ǿ6{Ѻ\\(ۆ1KQxTжТZ71n5Ϻ3Ȓ00`G*(VU.k_OܚL$;[fm]w{0)ҽ%[߆\u07fcnɷ72¨)7ȋ(r7>?yԏ@`_& :δ>d\u05ebHgђ&oB}Qك٦)D=Ǿ2tS|:F^:/C"ǖ*DԍZ˪wd},ϗP˝2gEwޮ"uMNtՙ}ȓN#;A[wqU/֑g}7305t^fw|C#7?\'߿\'fNz)ԋ@`ܵ\\\\0}ţϡtUq0ckJkLfEٸ.d5Gv4ڮCU.ԲDAƛQV5ǁrѣZ*֒ҍ_A8*Wy\\j6bQՉI3&YݍS(і\\D~q5Pr|\u06dd9O1gh4۵Y9@Ǟ}ҡɷ<=`Abc_VUEھUoޛqQF1fޚ]IGٷ\u070es/\\!crĮϒ ΥAhAY#HGO9%ݍwKyԌ&WlI):%ȕv d9xַfG<-'

LONG_VALID_ASCII = b'ovZBRVWvLXuvojXKFDGxsnGLIrZWDqlqvQfQitcIRJSNMDILbyHVxHOIkvYSuZqswIxvJKBenivpYVSkgJGdmMrclHLybHwHAhwCaHGakesRfRuOnwDGwJVNOczzJlhgGusUbQsAsgIWZBuQcaIKdvnxyTWjTuxZInLpZcerfJEwyHLgKylxPSPvUtPLcwXxAidVBiTcFdvjlgLEKNaZAIYpPRTHmFbByPMxkqEDThQyYrTfdWHPXQJCrzidedMDNUFLszfnGewDcvVaisFzGQdROplYcWsnMCSXcYOOqLJRurLmOCvsDLpxZkgPSXyDmyYJptKUmDFCzTaJcUFNzOgEfXUYdxmfwFSckrjXrHJzIpxACLwlfmvYPSHkOuMtRlCzDleHHEAOKPkCWYMKDDkCoPADUkSVFUeHbqiLiXVIGDDkEYGBXvuBlLGtkLcgjcHaByDRYggpOJNJjLyArtjOScBCLEYDGmVSnGAzmijeufMeXMUwtIKjCVVBVQiwFWWzzyeFsQnMXsWNeEHToyxooRUAQTkuhUCZKhhhzgIMnCykEvgwafjznlbhydGkCyZJVUuczmtrbNGDRAgawdEXAkMgZXODJcYpqKTdxoSEHVWOXaNpyUfvIGxypQdwZfJjoZzgjSrwhVhAYgbjwerEEDIOYdJMZLeDgtVtibTVoahPuYbWtCATmCngVTasceiNLwlVySxYCAzdtLmBqQdYPbyhcFkUPgWRBfmoexwOyHLemncxUSbEXwbHIaCIBSouJfvkUAUDvizBGBHPxKPKOMYoTWqbXIlhVuCQjAQAlcmHHCgTKBVUDmszSlaXcpJVqeyTvfJWvVqDeCbStpxBsACMMJRosaHnsvPcRsEELgiqMLxuXDVPfRcCXmKdrfvTZxrxxcHCdsqYGiYyADItuHBkSwnDDEHsbnZZzVMGqieOqEWzveHQbzHBVVhNwAMORoMgtpYghSlkCFAshNQxFKOnIhtRdvTrVaDOvftwLOmjRjCFSufLYCxwQOEyIKjHeYulvYwFIOygCvfysRIXOoJcUAqxYHifyNzidEKzeWTsqMDGvOGomyxHbcwQSmghZUbynfZFIJkhJkWDUOlRRDAkHOnxfzkoEDUuablcEZftxynHmOYiqMsPLSYvIdMgFTgQcxQgDSJOgQzhhfJLhrdywnKlOZCGYfzSIBcmMBQTWApbXaFnCThVBMwHPRtULPgTHXjjJoeLeWvzKvnpQNHfnpVWpcKWGjFVSwWYManeIQENRLiMFXhxcajJGoiPGBSzmdxPLexLGbgSgOnRYONLVFvPZAHqcNSLDvOCxPQOMRurFZlQuDDmrXiDazswsterxdfzUIvTuagFulOhaJDsVuBaTCTBrouNYmNkFTkmXQaXbiiEGzEUvJmJAZDhVRRHOMpYImIzIavpFaGChVhpAEqxXKFbwRNCMhadgbcCgsxQPHmXcedlaZWXubDBuxEdEWPCyfemGaMECSTYvUNGrACwMLcjXguCgPKZLTFSyMSAAFmNGkjSxCxcjXHCsgrwNduBGIJhjtSDcnxwMUdCsztkcsTecgrqocFTichqaCGxBHfRzJkeTTDvFwBiZDkjMBlYoAPmHOqJIgZOwLYCLhhBgHPDNrJZRvLgxtWlhXsJnTTbkgQQEqUkclOqgMwSklnTnQSabJeEHCOFxHrCqtoXJfRUfqjwtPsFKpnPzqXGmhweWlpVEswnuMSbjlmvcTwsVqhVJnPOluSezktsecSspBEikPyLAbMgMEnqhrFObxRipyARtmJXfopvgBhjjckZtjllyvtxeZXYoaGwwfKbtttIpPpjdqayYuLHazcXlHrIMyShFQOWWkUEuSHagNIQenBJKBTXyfJPbUbpEXvkbVGUtsxSUdZJryJpvRmGtgcQYpxqXklKwXJFBLemFmaNxddEfwASWiZUplbWyKgyFDwyEJZTlfPDzaKlfFDwjwtiFcdQobjJUFsPnegNOllRokmiESyyugPKjobJCtCObeSrLSqnEZvvKKtHJwVmyRRQCIBiSGgkuhqlvoaDkCnAQnUEHjRQgmQhfZhsVTgRaMnkIfeubWoljHOhJDqjAnlUbtAUAkRkGiOsIsSISBtdaqQkkNzPipCguPKzjqHSBZuJDGkQwAezrbuzLfMfLgmEHahoCsgznFiZHbqAnuiHYsFemqxFvXhgidFzVWnqwbEaUVtuJeQYUSDZXFBlIVTPTwcbsqUfhsgTgMvgTYpXaOyqrHvtsBAPGmzkAmyLwkCmSwkhArUjjfoKPVjnmRrayzlkphConTVFAOoLaGLuJakfvtagqRjNPUwaFJuUWHXMIqSZGSSPvlWksVtHyiKYJHCkjvQoEWoTrZNDMBJSAzJfrmvGibBLiOgcysBKhiYYGLbLYyAylxhWnFICoGAYGcPLAThBbgKbyzPohGZsACAKgsUxoiuCoGOiMLoIbBGeNVumWWdjsdAsjVvYOFTxbzeiGKqLPSyABOiXaaDDvRkZVrFqOwZoTvXENgSBjxkbhdCJcOXYuDPGCHpFOUirhMtBBVwXwiNZaVgRZjXlzRyqQzWojefJQIAUWmwICgRRTLJaeIBwgMTHDOMpoUdeZZKOKfPKBcoaiojBJIuQlovpXsgZCNPPQWErVwoTvrhKsmJknesHPRcdNURnfVBvTVVCWjGPeXkSPwcOprFllhmFDTolGSzpiwtrjkbEACkePmPNmBnuBVWOZyEZlfhetKhKsQywOfYHjIvzMlsLEnygQlkkPEoovSjAHVCIBpLfaeenzOskarULiMKOqoUbzZPKiJeHAHWulqtOPJOavmHaBbFnPtWwNmpWVbiEsSkavHwgBGsvSdIsXxolagzMUNQYPScwURiDxqNXOkBonEoUbyUqQLiBDxmwntrjZCIQGeKsZYSzoUxyelSBfeICtYguUzKPntYJCtsmUJVFysjLlhPXRfvMLZMGAXvjigBuTsggupOhAaYnZSmbLwQbsXghLAZOihXyEjJzMfyyXbdBXyLkamFNejwgayjqgSUoUAAkuScYNVziIMYrOxovavbYdFEkDQmODkMPgiIDPxKKWXeIydVCgboWOIWSWtObTOyaqBdJtRXKdSvrarZFrceBzGUYPLrDdmpFNrzgbZnispjHIMjcaQhpnVoDaIjiDuSfntMGSptERKAVsemjAZgWgafqoxtIGSeBGBieatFTdvDJVdqpOvWCRXJZYPjVPMWLtcfimJUrKRJyDgrKVJJdQSHQVKKfBQspxmrDdXdzsOwDiGLhXtDJVFkLHGFMWbVKuYntplvozLDjwZtHTuIdOxSTEuorpGdIjjTnWiANaTUyHSMPAYLTPjmyvRKUPvWWFCxaqprBJZGxkvyxayAwJjOYtIUICVqEnsGvsJeTKlpvkULEFMnhXfPtqpwNVIfePyTpOOSMBLlgvOIaqmPehyfmnecurJCTYMaXUvAulISTEQXYlFwLLBnimuMSNGLUsLGZpSIXSxTMcQsZYXkKQLoFqKlczKCqzVJOWiCowQBGSVQnKJgpRUEwRmHgjVphHaUVcNAnWGBeqVQMXyDSWXIDWenIRBPNplptqQCfharQHulnZLDuCVmstCiyZYthZcAeItHfMgqKTnijAsraGJbqohjePZTbQqGgnOyrHZrMWcATWoLUQidFdbFIgHTOcpXNQfEsvXClkpgOUoYKNsfPDSmHSsUiXDmFsAtvcKPRbbLHjhrylYwiIxOEnuXfiyklCEkIUjGrjEIhmHNnhQFMLGHCpZnEVtSDnOylXSHLoqeNMbzeMWmIZecPdQSxbwCoLWDHLuMdYDtuudyOsWcdefBBoKTZFrBJYgRQhspQpdbzoYUHiFcNzHyjxzpkLWlHYLMoWjkJmWUeaRyDOqXdqnehjGMKOUXrPZjZdjqLhmVgIOvPftcPJFMuJqRTGqYVnsdQCXPlgDTXhdkKUiDcLYTHouaVggHUfoOZgKccRYkpABxIuCFtyExYJGbHnTDxqqjeebjafiOwkpeoHxivFRCMdQCdcLMogJWjthofAejZReQjEjxYHaLatBqEvldiWdunONrqSRWSKuWFouYetAkGkDuTSEBpzIABCLOuMfQSyqECFqwNfECOOBUcdqLNXPzIpdIxiCqrqKlfnecSPvvThpIkxgscrgObiPIqfZukRYtEEzbzVNsBugFGMIERpThjQweoAldcduWmCaTmXmWPDDEksnyknHhdBvSFQIpmIlMjtotkhtvBpPcIfXHvBNyDGMsmTUDaAifdszQaQSOKLsAkdiFMjWKyujvwXekcOzrGtRisTwPRTEIXRTMyTonKEtlGpkiBPXRRHylEHXmCIADCyNVUSgIXncYXJaTNhxzEglnlznZbVrjaLqJabErLYejzTjvCoxcoihtXNQeWzXSizuuEHBNsHWFgucUgOvwzHWxzFAgEQlkspfVbFLSouoLPiMrhBqogpaKAVCKfQkyPplOgnlIrcstRjWvgJfpjNdYyHrGFeLETIBAodyqYiUkEyCnFawVpaZLcrRwSvSUYzqfQOTGDPOaugRQcSQjzTCGINOHFYSHialcKXfJbIeKwSvJnlJZtraQDZELztYaAzEkIdJmtFAVdDQwzBHpZDrARghtJOwDVwGLFUbojYasknvPUdKwDDPuBrhKnqkpuwMhbNpjrlDepjtQXaBwBHPWmmgQXETZdPaLuOPOHiNRQZrvgxeaDFaWAiXhkUOHHwowoIZAglPARMnWIZFCutBLyCChrCQhdWJQHKtZSnbNbCSeKVbCACzVRTBKpYOASPvpjXCYKrSqTMNbfAYBibkJcfPeDRGDxbNEMLYawmXoXuVdjmfPgATjSZWALIcAISkrmC'