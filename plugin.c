#include <stdint.h>
#include <stdlib.h>
#include <nfp/me.h>
#include <nfp/mem_atomic.h>
#include <pif_common.h>
#include <pif_plugin.h>
#include <pif_plugin_metadata.h>


__export __emem uint32_t white_flows = 0;
__export __emem uint32_t grey_flows = 0;
__export __emem uint32_t black_flows = 0;

int pif_plugin_set_x_factor(EXTRACTED_HEADERS_T* headers, MATCH_DATA_T* data)
{
    int x = pif_plugin_meta_get__factor__x(headers);
    int score = pif_plugin_meta_get__score_metadata__score(headers);
    pif_plugin_meta_set__score_metadata__score_quantified(headers,score/x);
    return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_split(EXTRACTED_HEADERS_T* headers, MATCH_DATA_T* data)
{
    int score = pif_plugin_meta_get__score_metadata__score(headers);
    int threshold_high = pif_plugin_meta_get__threshold__T_high(headers);
    int threshold_low = pif_plugin_meta_get__threshold__T_low(headers);

    if(score >= threshold_high)
    {
        pif_plugin_meta_set__standard_metadata__egress_spec(headers,0x0302);
        mem_incr32(&white_flows);
    }
    else if((score < threshold_high) && (score >= threshold_low))
    {
        pif_plugin_meta_set__standard_metadata__egress_spec(headers,0x0301);
        mem_incr32(&grey_flows);
    }
    else
    {
        mem_incr32(&black_flows);
        return PIF_PLUGIN_RETURN_DROP;
    }

    return PIF_PLUGIN_RETURN_FORWARD;
}
