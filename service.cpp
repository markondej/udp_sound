#include "udp_stream.hpp"
#include <iostream>
#include <csignal>
#include <cstring>

#define STREAM_SERVICE_NOP_DELAY 500000

float fir_44100[] = { 0.0000000f,-0.0000009f,0.0000002f,0.0000045f,0.0000111f,0.0000174f,0.0000202f,0.0000172f,0.0000085f,-0.0000030f,-0.0000125f,-0.0000151f,-0.0000080f,0.0000081f,0.0000286f,0.0000464f,0.0000544f,0.0000486f,0.0000295f,0.0000032f,-0.0000211f,-0.0000338f,-0.0000286f,-0.0000056f,0.0000285f,0.0000624f,0.0000836f,0.0000835f,0.0000605f,0.0000214f,-0.0000207f,-0.0000505f,-0.0000563f,-0.0000342f,0.0000095f,0.0000606f,0.0001010f,0.0001155f,0.0000974f,0.0000514f,-0.0000077f,-0.0000592f,-0.0000844f,-0.0000729f,-0.0000272f,0.0000382f,0.0001005f,0.0001373f,0.0001341f,0.0000901f,0.0000191f,-0.0000551f,-0.0001062f,-0.0001153f,-0.0000777f,-0.0000050f,0.0000780f,0.0001420f,0.0001633f,0.0001323f,0.0000580f,-0.0000354f,-0.0001155f,-0.0001539f,-0.0001359f,-0.0000662f,0.0000318f,0.0001240f,0.0001771f,0.0001707f,0.0001047f,0.0000000f,-0.0001079f,-0.0001815f,-0.0001942f,-0.0001402f,-0.0000371f,0.0000796f,0.0001685f,0.0001968f,0.0001524f,0.0000481f,-0.0000814f,-0.0001917f,-0.0002441f,-0.0002192f,-0.0001243f,0.0000082f,0.0001319f,0.0002023f,0.0001925f,0.0001032f,-0.0000369f,-0.0001805f,-0.0002778f,-0.0002943f,-0.0002229f,-0.0000877f,0.0000646f,0.0001798f,0.0002157f,0.0001569f,0.0000211f,-0.0001467f,-0.0002890f,-0.0003561f,-0.0003238f,-0.0002023f,-0.0000332f,0.0001240f,0.0002128f,0.0001994f,0.0000854f,-0.0000923f,-0.0002737f,-0.0003962f,-0.0004166f,-0.0003269f,-0.0001574f,0.0000328f,0.0001761f,0.0002200f,0.0001461f,-0.0000233f,-0.0002317f,-0.0004080f,-0.0004909f,-0.0004507f,-0.0003006f,-0.0000924f,0.0001005f,0.0002089f,0.0001918f,0.0000516f,-0.0001662f,-0.0003879f,-0.0005373f,-0.0005619f,-0.0004524f,-0.0002462f,-0.0000154f,0.0001580f,0.0002107f,0.0001207f,-0.0000845f,-0.0003364f,-0.0005491f,-0.0006487f,-0.0006001f,-0.0004193f,-0.0001691f,0.0000624f,0.0001920f,0.0001710f,0.0000027f,-0.0002581f,-0.0005231f,-0.0007011f,-0.0007302f,-0.0005993f,-0.0003536f,-0.0000789f,0.0001270f,0.0001893f,0.0000821f,-0.0001617f,-0.0004604f,-0.0007121f,-0.0008297f,-0.0007718f,-0.0005578f,-0.0002621f,0.0000111f,0.0001638f,0.0001388f,-0.0000598f,-0.0003669f,-0.0006785f,-0.0008877f,-0.0009214f,-0.0007673f,-0.0004785f,-0.0001562f,0.0000853f,0.0001581f,0.0000323f,-0.0002530f,-0.0006025f,-0.0008966f,-0.0010336f,-0.0009655f,-0.0007152f,-0.0003698f,-0.0000510f,0.0001270f,0.0000978f,-0.0001335f,-0.0004910f,-0.0008535f,-0.0010964f,-0.0011352f,-0.0009555f,-0.0006195f,-0.0002449f,0.0000357f,0.0001203f,-0.0000256f,-0.0003565f,-0.0007613f,-0.0011018f,-0.0012601f,-0.0011806f,-0.0008903f,-0.0004901f,-0.0001210f,0.0000852f,0.0000516f,-0.0002156f,-0.0006285f,-0.0010469f,-0.0013269f,-0.0013710f,-0.0011630f,-0.0007748f,-0.0003420f,-0.0000181f,0.0000797f,-0.0000882f,-0.0004692f,-0.0009352f,-0.0013269f,-0.0015085f,-0.0014164f,-0.0010815f,-0.0006203f,-0.0001950f,0.0000426f,0.0000044f,-0.0003025f,-0.0007768f,-0.0012573f,-0.0015785f,-0.0016284f,-0.0013887f,-0.0009419f,-0.0004442f,-0.0000716f,0.0000414f,-0.0001510f,-0.0005878f,-0.0011222f,-0.0015711f,-0.0017789f,-0.0016723f,-0.0012872f,-0.0007573f,-0.0002686f,0.0000047f,-0.0000385f,-0.0003899f,-0.0009331f,-0.0014834f,-0.0018510f,-0.0019075f,-0.0016318f,-0.0011186f,-0.0005470f,-0.0001190f,0.0000113f,-0.0002084f,-0.0007084f,-0.0013203f,-0.0018340f,-0.0020713f,-0.0019483f,-0.0015059f,-0.0008974f,-0.0003362f,-0.0000220f,-0.0000706f,-0.0004725f,-0.0010944f,-0.0017244f,-0.0021450f,-0.0022088f,-0.0018917f,-0.0013022f,-0.0006456f,-0.0001536f,-0.0000031f,-0.0002539f,-0.0008265f,-0.0015274f,-0.0021159f,-0.0023873f,-0.0022451f,-0.0017364f,-0.0010368f,-0.0003913f,-0.0000292f,-0.0000837f,-0.0005440f,-0.0012572f,-0.0019800f,-0.0024622f,-0.0025346f,-0.0021690f,-0.0014902f,-0.0007340f,-0.0001668f,0.0000078f,-0.0002793f,-0.0009368f,-0.0017423f,-0.0024186f,-0.0027301f,-0.0025653f,-0.0019781f,-0.0011708f,-0.0004255f,-0.0000065f,-0.0000676f,-0.0005969f,-0.0014182f,-0.0022510f,-0.0028065f,-0.0028891f,-0.0024659f,-0.0016804f,-0.0008051f,-0.0001476f,0.0000562f,-0.0002741f,-0.0010331f,-0.0019640f,-0.0027460f,-0.0031058f,-0.0029140f,-0.0022322f,-0.0012945f,-0.0004281f,0.0000603f,-0.0000085f,-0.0006212f,-0.0015738f,-0.0025405f,-0.0031856f,-0.0032809f,-0.0027873f,-0.0018713f,-0.0008497f,-0.0000810f,0.0001591f,-0.0002238f,-0.0011078f,-0.0021935f,-0.0031062f,-0.0035262f,-0.0033010f,-0.0025019f,-0.0014021f,-0.0003844f,0.0001909f,0.0001130f,-0.0006036f,-0.0017207f,-0.0028557f,-0.0036137f,-0.0037254f,-0.0031433f,-0.0020624f,-0.0008554f,0.0000547f,0.0003417f,-0.0001078f,-0.0011508f,-0.0024342f,-0.0035147f,-0.0040123f,-0.0037449f,-0.0027951f,-0.0014862f,-0.0002728f,0.0004158f,0.0003269f,-0.0005244f,-0.0018555f,-0.0032105f,-0.0041170f,-0.0042510f,-0.0035534f,-0.0022557f,-0.0008037f,0.0002941f,0.0006441f,0.0001071f,-0.0011473f,-0.0026950f,-0.0040007f,-0.0046038f,-0.0042807f,-0.0031285f,-0.0015369f,-0.0000575f,0.0007864f,0.0006837f,-0.0003508f,-0.0019752f,-0.0036335f,-0.0047461f,-0.0049126f,-0.0040563f,-0.0024575f,-0.0006634f,0.0006985f,0.0011386f,0.0004799f,-0.0010725f,-0.0029955f,-0.0046235f,-0.0053794f,-0.0049789f,-0.0035372f,-0.0015377f,0.0003284f,0.0014002f,0.0012799f,-0.0000214f,-0.0020772f,-0.0041852f,-0.0056067f,-0.0058255f,-0.0047346f,-0.0026848f,-0.0003732f,0.0013923f,0.0019737f,0.0011322f,-0.0008774f,-0.0033818f,-0.0055146f,-0.0065151f,-0.0059986f,-0.0041030f,-0.0014561f,0.0010310f,0.0024752f,0.0023329f,0.0006023f,-0.0021590f,-0.0050121f,-0.0069542f,-0.0072701f,-0.0057930f,-0.0029828f,0.0002145f,0.0026822f,0.0035202f,0.0023699f,-0.0004391f,-0.0039789f,-0.0070273f,-0.0084866f,-0.0077757f,-0.0050561f,-0.0012058f,0.0024594f,0.0046312f,0.0044703f,0.0019241f,-0.0022189f,-0.0065665f,-0.0095858f,-0.0101365f,-0.0078938f,-0.0035052f,0.0015857f,0.0056057f,0.0070591f,0.0052726f,0.0006813f,-0.0052564f,-0.0105096f,-0.0131547f,-0.0120615f,-0.0073483f,-0.0004288f,0.0063894f,0.0106504f,0.0106040f,0.0058813f,-0.0022553f,-0.0112083f,-0.0178311f,-0.0194778f,-0.0149811f,-0.0052227f,0.0069381f,0.0174135f,0.0221383f,0.0184638f,0.0062613f,-0.0116436f,-0.0299084f,-0.0419336f,-0.0416395f,-0.0252817f,0.0072205f,0.0518560f,0.1011722f,0.1458834f,0.1770421f,0.1882086f,0.1770421f,0.1458834f,0.1011722f,0.0518560f,0.0072205f,-0.0252817f,-0.0416395f,-0.0419336f,-0.0299084f,-0.0116436f,0.0062613f,0.0184638f,0.0221383f,0.0174135f,0.0069381f,-0.0052227f,-0.0149811f,-0.0194778f,-0.0178311f,-0.0112083f,-0.0022553f,0.0058813f,0.0106040f,0.0106504f,0.0063894f,-0.0004288f,-0.0073483f,-0.0120615f,-0.0131547f,-0.0105096f,-0.0052564f,0.0006813f,0.0052726f,0.0070591f,0.0056057f,0.0015857f,-0.0035052f,-0.0078938f,-0.0101365f,-0.0095858f,-0.0065665f,-0.0022189f,0.0019241f,0.0044703f,0.0046312f,0.0024594f,-0.0012058f,-0.0050561f,-0.0077757f,-0.0084866f,-0.0070273f,-0.0039789f,-0.0004391f,0.0023699f,0.0035202f,0.0026822f,0.0002145f,-0.0029828f,-0.0057930f,-0.0072701f,-0.0069542f,-0.0050121f,-0.0021590f,0.0006023f,0.0023329f,0.0024752f,0.0010310f,-0.0014561f,-0.0041030f,-0.0059986f,-0.0065151f,-0.0055146f,-0.0033818f,-0.0008774f,0.0011322f,0.0019737f,0.0013923f,-0.0003732f,-0.0026848f,-0.0047346f,-0.0058255f,-0.0056067f,-0.0041852f,-0.0020772f,-0.0000214f,0.0012799f,0.0014002f,0.0003284f,-0.0015377f,-0.0035372f,-0.0049789f,-0.0053794f,-0.0046235f,-0.0029955f,-0.0010725f,0.0004799f,0.0011386f,0.0006985f,-0.0006634f,-0.0024575f,-0.0040563f,-0.0049126f,-0.0047461f,-0.0036335f,-0.0019752f,-0.0003508f,0.0006837f,0.0007864f,-0.0000575f,-0.0015369f,-0.0031285f,-0.0042807f,-0.0046038f,-0.0040007f,-0.0026950f,-0.0011473f,0.0001071f,0.0006441f,0.0002941f,-0.0008037f,-0.0022557f,-0.0035534f,-0.0042510f,-0.0041170f,-0.0032105f,-0.0018555f,-0.0005244f,0.0003269f,0.0004158f,-0.0002728f,-0.0014862f,-0.0027951f,-0.0037449f,-0.0040123f,-0.0035147f,-0.0024342f,-0.0011508f,-0.0001078f,0.0003417f,0.0000547f,-0.0008554f,-0.0020624f,-0.0031433f,-0.0037254f,-0.0036137f,-0.0028557f,-0.0017207f,-0.0006036f,0.0001130f,0.0001909f,-0.0003844f,-0.0014021f,-0.0025019f,-0.0033010f,-0.0035262f,-0.0031062f,-0.0021935f,-0.0011078f,-0.0002238f,0.0001591f,-0.0000810f,-0.0008497f,-0.0018713f,-0.0027873f,-0.0032809f,-0.0031856f,-0.0025405f,-0.0015738f,-0.0006212f,-0.0000085f,0.0000603f,-0.0004281f,-0.0012945f,-0.0022322f,-0.0029140f,-0.0031058f,-0.0027460f,-0.0019640f,-0.0010331f,-0.0002741f,0.0000562f,-0.0001476f,-0.0008051f,-0.0016804f,-0.0024659f,-0.0028891f,-0.0028065f,-0.0022510f,-0.0014182f,-0.0005969f,-0.0000676f,-0.0000065f,-0.0004255f,-0.0011708f,-0.0019781f,-0.0025653f,-0.0027301f,-0.0024186f,-0.0017423f,-0.0009368f,-0.0002793f,0.0000078f,-0.0001668f,-0.0007340f,-0.0014902f,-0.0021690f,-0.0025346f,-0.0024622f,-0.0019800f,-0.0012572f,-0.0005440f,-0.0000837f,-0.0000292f,-0.0003913f,-0.0010368f,-0.0017364f,-0.0022451f,-0.0023873f,-0.0021159f,-0.0015274f,-0.0008265f,-0.0002539f,-0.0000031f,-0.0001536f,-0.0006456f,-0.0013022f,-0.0018917f,-0.0022088f,-0.0021450f,-0.0017244f,-0.0010944f,-0.0004725f,-0.0000706f,-0.0000220f,-0.0003362f,-0.0008974f,-0.0015059f,-0.0019483f,-0.0020713f,-0.0018340f,-0.0013203f,-0.0007084f,-0.0002084f,0.0000113f,-0.0001190f,-0.0005470f,-0.0011186f,-0.0016318f,-0.0019075f,-0.0018510f,-0.0014834f,-0.0009331f,-0.0003899f,-0.0000385f,0.0000047f,-0.0002686f,-0.0007573f,-0.0012872f,-0.0016723f,-0.0017789f,-0.0015711f,-0.0011222f,-0.0005878f,-0.0001510f,0.0000414f,-0.0000716f,-0.0004442f,-0.0009419f,-0.0013887f,-0.0016284f,-0.0015785f,-0.0012573f,-0.0007768f,-0.0003025f,0.0000044f,0.0000426f,-0.0001950f,-0.0006203f,-0.0010815f,-0.0014164f,-0.0015085f,-0.0013269f,-0.0009352f,-0.0004692f,-0.0000882f,0.0000797f,-0.0000181f,-0.0003420f,-0.0007748f,-0.0011630f,-0.0013710f,-0.0013269f,-0.0010469f,-0.0006285f,-0.0002156f,0.0000516f,0.0000852f,-0.0001210f,-0.0004901f,-0.0008903f,-0.0011806f,-0.0012601f,-0.0011018f,-0.0007613f,-0.0003565f,-0.0000256f,0.0001203f,0.0000357f,-0.0002449f,-0.0006195f,-0.0009555f,-0.0011352f,-0.0010964f,-0.0008535f,-0.0004910f,-0.0001335f,0.0000978f,0.0001270f,-0.0000510f,-0.0003698f,-0.0007152f,-0.0009655f,-0.0010336f,-0.0008966f,-0.0006025f,-0.0002530f,0.0000323f,0.0001581f,0.0000853f,-0.0001562f,-0.0004785f,-0.0007673f,-0.0009214f,-0.0008877f,-0.0006785f,-0.0003669f,-0.0000598f,0.0001388f,0.0001638f,0.0000111f,-0.0002621f,-0.0005578f,-0.0007718f,-0.0008297f,-0.0007121f,-0.0004604f,-0.0001617f,0.0000821f,0.0001893f,0.0001270f,-0.0000789f,-0.0003536f,-0.0005993f,-0.0007302f,-0.0007011f,-0.0005231f,-0.0002581f,0.0000027f,0.0001710f,0.0001920f,0.0000624f,-0.0001691f,-0.0004193f,-0.0006001f,-0.0006487f,-0.0005491f,-0.0003364f,-0.0000845f,0.0001207f,0.0002107f,0.0001580f,-0.0000154f,-0.0002462f,-0.0004524f,-0.0005619f,-0.0005373f,-0.0003879f,-0.0001662f,0.0000516f,0.0001918f,0.0002089f,0.0001005f,-0.0000924f,-0.0003006f,-0.0004507f,-0.0004909f,-0.0004080f,-0.0002317f,-0.0000233f,0.0001461f,0.0002200f,0.0001761f,0.0000328f,-0.0001574f,-0.0003269f,-0.0004166f,-0.0003962f,-0.0002737f,-0.0000923f,0.0000854f,0.0001994f,0.0002128f,0.0001240f,-0.0000332f,-0.0002023f,-0.0003238f,-0.0003561f,-0.0002890f,-0.0001467f,0.0000211f,0.0001569f,0.0002157f,0.0001798f,0.0000646f,-0.0000877f,-0.0002229f,-0.0002943f,-0.0002778f,-0.0001805f,-0.0000369f,0.0001032f,0.0001925f,0.0002023f,0.0001319f,0.0000082f,-0.0001243f,-0.0002192f,-0.0002441f,-0.0001917f,-0.0000814f,0.0000481f,0.0001524f,0.0001968f,0.0001685f,0.0000796f,-0.0000371f,-0.0001402f,-0.0001942f,-0.0001815f,-0.0001079f,0.0000000f,0.0001047f,0.0001707f,0.0001771f,0.0001240f,0.0000318f,-0.0000662f,-0.0001359f,-0.0001539f,-0.0001155f,-0.0000354f,0.0000580f,0.0001323f,0.0001633f,0.0001420f,0.0000780f,-0.0000050f,-0.0000777f,-0.0001153f,-0.0001062f,-0.0000551f,0.0000191f,0.0000901f,0.0001341f,0.0001373f,0.0001005f,0.0000382f,-0.0000272f,-0.0000729f,-0.0000844f,-0.0000592f,-0.0000077f,0.0000514f,0.0000974f,0.0001155f,0.0001010f,0.0000606f,0.0000095f,-0.0000342f,-0.0000563f,-0.0000505f,-0.0000207f,0.0000214f,0.0000605f,0.0000835f,0.0000836f,0.0000624f,0.0000285f,-0.0000056f,-0.0000286f,-0.0000338f,-0.0000211f,0.0000032f,0.0000295f,0.0000486f,0.0000544f,0.0000464f,0.0000286f,0.0000081f,-0.0000080f,-0.0000151f,-0.0000125f,-0.0000030f,0.0000085f,0.0000172f,0.0000202f,0.0000174f,0.0000111f,0.0000045f,0.0000002f,-0.0000009f };
float fir_22050[] = { 0.0000000f,0.0000001f,-0.0000002f,-0.0000082f,-0.0000177f,-0.0000152f,-0.0000017f,0.0000024f,-0.0000153f,-0.0000376f,-0.0000354f,-0.0000087f,0.0000074f,-0.0000141f,-0.0000520f,-0.0000585f,-0.0000220f,0.0000117f,-0.0000054f,-0.0000582f,-0.0000812f,-0.0000418f,0.0000122f,0.0000086f,-0.0000547f,-0.0001000f,-0.0000669f,0.0000063f,0.0000249f,-0.0000409f,-0.0001114f,-0.0000948f,-0.0000075f,0.0000399f,-0.0000178f,-0.0001121f,-0.0001220f,-0.0000296f,0.0000501f,0.0000121f,-0.0001003f,-0.0001444f,-0.0000587f,0.0000522f,0.0000455f,-0.0000752f,-0.0001578f,-0.0000922f,0.0000439f,0.0000780f,-0.0000377f,-0.0001584f,-0.0001264f,0.0000245f,0.0001052f,0.0000097f,-0.0001435f,-0.0001565f,-0.0000053f,0.0001228f,0.0000633f,-0.0001116f,-0.0001775f,-0.0000430f,0.0001276f,0.0001179f,-0.0000630f,-0.0001844f,-0.0000847f,0.0001177f,0.0001682f,0.0000000f,-0.0001734f,-0.0001251f,0.0000929f,0.0002085f,0.0000734f,-0.0001418f,-0.0001582f,0.0000550f,0.0002341f,0.0001518f,-0.0000888f,-0.0001779f,0.0000079f,0.0002415f,0.0002285f,-0.0000160f,-0.0001786f,-0.0000431f,0.0002292f,0.0002968f,0.0000731f,-0.0001562f,-0.0000910f,0.0001977f,0.0003500f,0.0001728f,-0.0001082f,-0.0001286f,0.0001499f,0.0003827f,0.0002760f,-0.0000346f,-0.0001486f,0.0000912f,0.0003912f,0.0003744f,0.0000619f,-0.0001448f,0.0000284f,0.0003743f,0.0004596f,0.0001765f,-0.0001126f,-0.0000299f,0.0003333f,0.0005241f,0.0003016f,-0.0000499f,-0.0000750f,0.0002724f,0.0005616f,0.0004284f,0.0000426f,-0.0000985f,0.0001982f,0.0005684f,0.0005467f,0.0001613f,-0.0000932f,0.0001195f,0.0005433f,0.0006469f,0.0002995f,-0.0000542f,0.0000465f,0.0004886f,0.0007198f,0.0004481f,0.0000204f,-0.0000106f,0.0004097f,0.0007587f,0.0005961f,0.0001291f,-0.0000419f,0.0003149f,0.0007594f,0.0007318f,0.0002673f,-0.0000393f,0.0002148f,0.0007213f,0.0008436f,0.0004265f,0.0000024f,0.0001214f,0.0006475f,0.0009213f,0.0005957f,0.0000850f,0.0000468f,0.0005446f,0.0009571f,0.0007621f,0.0002065f,0.0000023f,0.0004229f,0.0009468f,0.0009118f,0.0003608f,-0.0000031f,0.0002949f,0.0008899f,0.0010315f,0.0005379f,0.0000366f,0.0001745f,0.0007906f,0.0011096f,0.0007247f,0.0001230f,0.0000759f,0.0006570f,0.0011375f,0.0009063f,0.0002534f,0.0000120f,0.0005012f,0.0011104f,0.0010666f,0.0004204f,-0.0000068f,0.0003380f,0.0010285f,0.0011904f,0.0006123f,0.0000258f,0.0001834f,0.0008969f,0.0012645f,0.0008139f,0.0001117f,0.0000540f,0.0007254f,0.0012794f,0.0010078f,0.0002474f,-0.0000355f,0.0005280f,0.0012301f,0.0011757f,0.0004242f,-0.0000735f,0.0003219f,0.0011170f,0.0013003f,0.0006285f,-0.0000526f,0.0001260f,0.0009462f,0.0013667f,0.0008428f,0.0000290f,-0.0000411f,0.0007294f,0.0013643f,0.0010472f,0.0001672f,-0.0001625f,0.0004829f,0.0012875f,0.0012209f,0.0003519f,-0.0002246f,0.0002266f,0.0011373f,0.0013442f,0.0005676f,-0.0002194f,-0.0000179f,0.0009210f,0.0014002f,0.0007942f,-0.0001447f,-0.0002291f,0.0006520f,0.0013771f,0.0010090f,-0.0000053f,-0.0003876f,0.0003493f,0.0012688f,0.0011884f,0.0001873f,-0.0004781f,0.0000358f,0.0010766f,0.0013100f,0.0004153f,-0.0004912f,-0.0002639f,0.0008090f,0.0013548f,0.0006560f,-0.0004244f,-0.0005249f,0.0004816f,0.0013092f,0.0008835f,-0.0002831f,-0.0007251f,0.0001161f,0.0011667f,0.0010709f,-0.0000804f,-0.0008469f,-0.0002612f,0.0009287f,0.0011928f,0.0001636f,-0.0008793f,-0.0006220f,0.0006050f,0.0012276f,0.0004230f,-0.0008193f,-0.0009378f,0.0002136f,0.0011600f,0.0006685f,-0.0006730f,-0.0011832f,-0.0002207f,0.0009822f,0.0008695f,-0.0004549f,-0.0013377f,-0.0006680f,0.0006959f,0.0009968f,-0.0001879f,-0.0013885f,-0.0010955f,0.0003122f,0.0010258f,0.0000987f,-0.0013320f,-0.0014706f,-0.0001483f,0.0009386f,0.0003714f,-0.0011744f,-0.0017637f,-0.0006575f,0.0007263f,0.0005952f,-0.0009322f,-0.0019513f,-0.0011809f,0.0003904f,0.0007366f,-0.0006312f,-0.0020179f,-0.0016810f,-0.0000566f,0.0007670f,-0.0003046f,-0.0019588f,-0.0021200f,-0.0005917f,0.0006655f,0.0000092f,-0.0017804f,-0.0024635f,-0.0011825f,0.0004212f,0.0002698f,-0.0015012f,-0.0026835f,-0.0017896f,0.0000353f,0.0004384f,-0.0011500f,-0.0027617f,-0.0023697f,-0.0004789f,0.0004814f,-0.0007649f,-0.0026913f,-0.0028787f,-0.0010952f,0.0003737f,-0.0003902f,-0.0024789f,-0.0032761f,-0.0017769f,0.0001017f,-0.0000726f,-0.0021444f,-0.0035286f,-0.0024787f,-0.0003349f,0.0001420f,-0.0017207f,-0.0036131f,-0.0031501f,-0.0009216f,0.0002137f,-0.0012512f,-0.0035204f,-0.0037393f,-0.0016296f,0.0001114f,-0.0007872f,-0.0032560f,-0.0041979f,-0.0024171f,-0.0001828f,-0.0003839f,-0.0028416f,-0.0044849f,-0.0032316f,-0.0006715f,-0.0000959f,-0.0023138f,-0.0045712f,-0.0040138f,-0.0013404f,0.0000275f,-0.0017226f,-0.0044427f,-0.0047021f,-0.0021580f,-0.0000527f,-0.0011280f,-0.0041028f,-0.0052372f,-0.0030770f,-0.0003617f,-0.0005961f,-0.0035737f,-0.0055676f,-0.0040366f,-0.0009068f,-0.0001934f,-0.0028959f,-0.0056543f,-0.0049664f,-0.0016759f,0.0000178f,-0.0021266f,-0.0054752f,-0.0057914f,-0.0026360f,-0.0000145f,-0.0013367f,-0.0050281f,-0.0064371f,-0.0037347f,-0.0003272f,-0.0006061f,-0.0043330f,-0.0068359f,-0.0049016f,-0.0009378f,-0.0000186f,-0.0034325f,-0.0069325f,-0.0060526f,-0.0018411f,0.0003441f,-0.0023905f,-0.0066893f,-0.0070945f,-0.0030074f,0.0004087f,-0.0012898f,-0.0060905f,-0.0079307f,-0.0043826f,0.0001160f,-0.0002282f,-0.0051456f,-0.0084672f,-0.0058888f,-0.0005739f,0.0006866f,-0.0038904f,-0.0086188f,-0.0074277f,-0.0016774f,0.0013423f,-0.0023876f,-0.0083145f,-0.0088841f,-0.0031853f,0.0016277f,-0.0007252f,-0.0075016f,-0.0101298f,-0.0050613f,0.0014369f,0.0009861f,-0.0061477f,-0.0110281f,-0.0072435f,0.0006717f,0.0026155f,-0.0042406f,-0.0114348f,-0.0096470f,-0.0007596f,0.0040141f,-0.0017829f,-0.0111962f,-0.0121685f,-0.0029514f,0.0050131f,0.0012190f,-0.0101360f,-0.0146920f,-0.0060237f,0.0054131f,0.0047798f,-0.0080200f,-0.0170958f,-0.0101794f,0.0049489f,0.0089906f,-0.0044603f,-0.0192599f,-0.0158531f,0.0031832f,0.0141652f,0.0013667f,-0.0210736f,-0.0241774f,-0.0008594f,0.0213360f,0.0117789f,-0.0224423f,-0.0389917f,-0.0104530f,0.0348465f,0.0369427f,-0.0232938f,-0.0838825f,-0.0505685f,0.1037167f,0.2917702f,0.3764172f,0.2917702f,0.1037167f,-0.0505685f,-0.0838825f,-0.0232938f,0.0369427f,0.0348465f,-0.0104530f,-0.0389917f,-0.0224423f,0.0117789f,0.0213360f,-0.0008594f,-0.0241774f,-0.0210736f,0.0013667f,0.0141652f,0.0031832f,-0.0158531f,-0.0192599f,-0.0044603f,0.0089906f,0.0049489f,-0.0101794f,-0.0170958f,-0.0080200f,0.0047798f,0.0054131f,-0.0060237f,-0.0146920f,-0.0101360f,0.0012190f,0.0050131f,-0.0029514f,-0.0121685f,-0.0111962f,-0.0017829f,0.0040141f,-0.0007596f,-0.0096470f,-0.0114348f,-0.0042406f,0.0026155f,0.0006717f,-0.0072435f,-0.0110281f,-0.0061477f,0.0009861f,0.0014369f,-0.0050613f,-0.0101298f,-0.0075016f,-0.0007252f,0.0016277f,-0.0031853f,-0.0088841f,-0.0083145f,-0.0023876f,0.0013423f,-0.0016774f,-0.0074277f,-0.0086188f,-0.0038904f,0.0006866f,-0.0005739f,-0.0058888f,-0.0084672f,-0.0051456f,-0.0002282f,0.0001160f,-0.0043826f,-0.0079307f,-0.0060905f,-0.0012898f,0.0004087f,-0.0030074f,-0.0070945f,-0.0066893f,-0.0023905f,0.0003441f,-0.0018411f,-0.0060526f,-0.0069325f,-0.0034325f,-0.0000186f,-0.0009378f,-0.0049016f,-0.0068359f,-0.0043330f,-0.0006061f,-0.0003272f,-0.0037347f,-0.0064371f,-0.0050281f,-0.0013367f,-0.0000145f,-0.0026360f,-0.0057914f,-0.0054752f,-0.0021266f,0.0000178f,-0.0016759f,-0.0049664f,-0.0056543f,-0.0028959f,-0.0001934f,-0.0009068f,-0.0040366f,-0.0055676f,-0.0035737f,-0.0005961f,-0.0003617f,-0.0030770f,-0.0052372f,-0.0041028f,-0.0011280f,-0.0000527f,-0.0021580f,-0.0047021f,-0.0044427f,-0.0017226f,0.0000275f,-0.0013404f,-0.0040138f,-0.0045712f,-0.0023138f,-0.0000959f,-0.0006715f,-0.0032316f,-0.0044849f,-0.0028416f,-0.0003839f,-0.0001828f,-0.0024171f,-0.0041979f,-0.0032560f,-0.0007872f,0.0001114f,-0.0016296f,-0.0037393f,-0.0035204f,-0.0012512f,0.0002137f,-0.0009216f,-0.0031501f,-0.0036131f,-0.0017207f,0.0001420f,-0.0003349f,-0.0024787f,-0.0035286f,-0.0021444f,-0.0000726f,0.0001017f,-0.0017769f,-0.0032761f,-0.0024789f,-0.0003902f,0.0003737f,-0.0010952f,-0.0028787f,-0.0026913f,-0.0007649f,0.0004814f,-0.0004789f,-0.0023697f,-0.0027617f,-0.0011500f,0.0004384f,0.0000353f,-0.0017896f,-0.0026835f,-0.0015012f,0.0002698f,0.0004212f,-0.0011825f,-0.0024635f,-0.0017804f,0.0000092f,0.0006655f,-0.0005917f,-0.0021200f,-0.0019588f,-0.0003046f,0.0007670f,-0.0000566f,-0.0016810f,-0.0020179f,-0.0006312f,0.0007366f,0.0003904f,-0.0011809f,-0.0019513f,-0.0009322f,0.0005952f,0.0007263f,-0.0006575f,-0.0017637f,-0.0011744f,0.0003714f,0.0009386f,-0.0001483f,-0.0014706f,-0.0013320f,0.0000987f,0.0010258f,0.0003122f,-0.0010955f,-0.0013885f,-0.0001879f,0.0009968f,0.0006959f,-0.0006680f,-0.0013377f,-0.0004549f,0.0008695f,0.0009822f,-0.0002207f,-0.0011832f,-0.0006730f,0.0006685f,0.0011600f,0.0002136f,-0.0009378f,-0.0008193f,0.0004230f,0.0012276f,0.0006050f,-0.0006220f,-0.0008793f,0.0001636f,0.0011928f,0.0009287f,-0.0002612f,-0.0008469f,-0.0000804f,0.0010709f,0.0011667f,0.0001161f,-0.0007251f,-0.0002831f,0.0008835f,0.0013092f,0.0004816f,-0.0005249f,-0.0004244f,0.0006560f,0.0013548f,0.0008090f,-0.0002639f,-0.0004912f,0.0004153f,0.0013100f,0.0010766f,0.0000358f,-0.0004781f,0.0001873f,0.0011884f,0.0012688f,0.0003493f,-0.0003876f,-0.0000053f,0.0010090f,0.0013771f,0.0006520f,-0.0002291f,-0.0001447f,0.0007942f,0.0014002f,0.0009210f,-0.0000179f,-0.0002194f,0.0005676f,0.0013442f,0.0011373f,0.0002266f,-0.0002246f,0.0003519f,0.0012209f,0.0012875f,0.0004829f,-0.0001625f,0.0001672f,0.0010472f,0.0013643f,0.0007294f,-0.0000411f,0.0000290f,0.0008428f,0.0013667f,0.0009462f,0.0001260f,-0.0000526f,0.0006285f,0.0013003f,0.0011170f,0.0003219f,-0.0000735f,0.0004242f,0.0011757f,0.0012301f,0.0005280f,-0.0000355f,0.0002474f,0.0010078f,0.0012794f,0.0007254f,0.0000540f,0.0001117f,0.0008139f,0.0012645f,0.0008969f,0.0001834f,0.0000258f,0.0006123f,0.0011904f,0.0010285f,0.0003380f,-0.0000068f,0.0004204f,0.0010666f,0.0011104f,0.0005012f,0.0000120f,0.0002534f,0.0009063f,0.0011375f,0.0006570f,0.0000759f,0.0001230f,0.0007247f,0.0011096f,0.0007906f,0.0001745f,0.0000366f,0.0005379f,0.0010315f,0.0008899f,0.0002949f,-0.0000031f,0.0003608f,0.0009118f,0.0009468f,0.0004229f,0.0000023f,0.0002065f,0.0007621f,0.0009571f,0.0005446f,0.0000468f,0.0000850f,0.0005957f,0.0009213f,0.0006475f,0.0001214f,0.0000024f,0.0004265f,0.0008436f,0.0007213f,0.0002148f,-0.0000393f,0.0002673f,0.0007318f,0.0007594f,0.0003149f,-0.0000419f,0.0001291f,0.0005961f,0.0007587f,0.0004097f,-0.0000106f,0.0000204f,0.0004481f,0.0007198f,0.0004886f,0.0000465f,-0.0000542f,0.0002995f,0.0006469f,0.0005433f,0.0001195f,-0.0000932f,0.0001613f,0.0005467f,0.0005684f,0.0001982f,-0.0000985f,0.0000426f,0.0004284f,0.0005616f,0.0002724f,-0.0000750f,-0.0000499f,0.0003016f,0.0005241f,0.0003333f,-0.0000299f,-0.0001126f,0.0001765f,0.0004596f,0.0003743f,0.0000284f,-0.0001448f,0.0000619f,0.0003744f,0.0003912f,0.0000912f,-0.0001486f,-0.0000346f,0.0002760f,0.0003827f,0.0001499f,-0.0001286f,-0.0001082f,0.0001728f,0.0003500f,0.0001977f,-0.0000910f,-0.0001562f,0.0000731f,0.0002968f,0.0002292f,-0.0000431f,-0.0001786f,-0.0000160f,0.0002285f,0.0002415f,0.0000079f,-0.0001779f,-0.0000888f,0.0001518f,0.0002341f,0.0000550f,-0.0001582f,-0.0001418f,0.0000734f,0.0002085f,0.0000929f,-0.0001251f,-0.0001734f,0.0000000f,0.0001682f,0.0001177f,-0.0000847f,-0.0001844f,-0.0000630f,0.0001179f,0.0001276f,-0.0000430f,-0.0001775f,-0.0001116f,0.0000633f,0.0001228f,-0.0000053f,-0.0001565f,-0.0001435f,0.0000097f,0.0001052f,0.0000245f,-0.0001264f,-0.0001584f,-0.0000377f,0.0000780f,0.0000439f,-0.0000922f,-0.0001578f,-0.0000752f,0.0000455f,0.0000522f,-0.0000587f,-0.0001444f,-0.0001003f,0.0000121f,0.0000501f,-0.0000296f,-0.0001220f,-0.0001121f,-0.0000178f,0.0000399f,-0.0000075f,-0.0000948f,-0.0001114f,-0.0000409f,0.0000249f,0.0000063f,-0.0000669f,-0.0001000f,-0.0000547f,0.0000086f,0.0000122f,-0.0000418f,-0.0000812f,-0.0000582f,-0.0000054f,0.0000117f,-0.0000220f,-0.0000585f,-0.0000520f,-0.0000141f,0.0000074f,-0.0000087f,-0.0000354f,-0.0000376f,-0.0000153f,0.0000024f,-0.0000017f,-0.0000152f,-0.0000177f,-0.0000082f,-0.0000002f,0.0000001f };

udpstream::Service *service = nullptr;

void signalHandler(int sigNum)
{
    if ((service != nullptr) && service->IsEnabled()) {
        service->Disable();
    }
}

int main(int argc, char** argv)
{
    std::string address = UDP_STREAM_DEFAULT_ADDRESS, device = UDP_STREAM_DEFAULT_INPUT_DEVICE;
    uint32_t samplingRate = UDP_STREAM_DEFAULT_SAMPLE_RATE;
    uint16_t port = UDP_STREAM_DEFAULT_PORT;
    uint8_t channels = UDP_STREAM_DEFAULT_CHANNELS, bitsPerChannel = UDP_STREAM_DEFAULT_BITS;
	std::atomic_bool useFir(false);

    if (argc > 1) { address = argv[1]; }
    if (argc > 2) { port = std::stoi(argv[2]); }
    if (argc > 3) { device = argv[3]; }
    if (argc > 4) { samplingRate = std::stoi(argv[4]); }
    if (argc > 5) { channels = std::stoi(argv[5]); }
    if (argc > 6) { bitsPerChannel = std::stoi(argv[6]); }
    if (argc > 7) { useFir = static_cast<bool>(std::stoi(argv[7])); }

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTSTP, signalHandler);

    int result = EXIT_SUCCESS;

    std::vector<uint8_t> *input = nullptr;

    try {
        service = new udpstream::Service(
            [&](uint32_t samplingRate, uint8_t channels, uint8_t bitsPerChannel, uint8_t *data, std::size_t size) {
                if (!useFir) {
					return;
                }
				
				std::size_t filterSize = 0;
                float *firFilter = nullptr;

                if (channels != 1) {
                    return;
                }

                switch (samplingRate) {
                case 44100:
                    firFilter = fir_44100;
                    filterSize = sizeof(fir_44100) / sizeof(float);
                    break;
                case 22050:
                    firFilter = fir_22050;
                    filterSize = sizeof(fir_22050) / sizeof(float);
                    break;
                default:
                    break;
                }

                unsigned bytesPerChannel = bitsPerChannel >> 3;

                if ((firFilter != nullptr) && filterSize) {
                    if (input == nullptr) {
                        std::cout << "Using size " << filterSize << " FIR filter" << std::endl;
                        input = new std::vector<uint8_t>();
                    }
                    std::size_t offset = input->size();
                    input->resize(offset + size);
                    std::memcpy(&(*input)[offset], data, size);

                    std::memset(data, 0x00, size);
                    std::size_t inputs = (input->size() >> (bytesPerChannel >> 1));
                    if (inputs >= filterSize) {
                        std::size_t offset = size - bytesPerChannel;
                        for (std::size_t i = inputs - 1; i >= filterSize - 1; i--) {
                            float output = 0.0f;
                            for (std::size_t j = 0; j < filterSize; j++) {
                                output += ((bytesPerChannel > 1) ? static_cast<float>((reinterpret_cast<int16_t *>(input->data()))[i - j]) : static_cast<float>((*input)[i - j]) - 0x7f)  * firFilter[j];
                            }
                            if (bytesPerChannel > 1) {
                                data[offset] = static_cast<int16_t>(output) & 0xff;
                                data[offset + 1] = static_cast<int16_t>(output) >> 8;
                            } else {
                                data[offset] = static_cast<uint8_t>(output + 0x7f);
                            }
                            offset -= bytesPerChannel;
                        }
                        input->erase(input->begin(), input->begin() + ((inputs - filterSize + 1) << (bytesPerChannel >> 1)));
                    }
                }
            }, [&](const std::exception &exception) {
                std::cout << exception.what() << std::endl;
            }, [&](const std::string &text) {
                std::cout << text << std::endl;
            });
        service->Enable(
            address,
            port,
            device,
            samplingRate,
            channels,
            bitsPerChannel
        );
        while (service->IsEnabled()) {
            std::this_thread::sleep_for(std::chrono::microseconds(STREAM_SERVICE_NOP_DELAY));
        }
    } catch (...) {
        result = EXIT_FAILURE;
    }

    if (service != nullptr) {
        auto temp = service;
        service = nullptr;
        delete temp;
    }
    if (input != nullptr) {
        delete input;
    }
    return result;
}
