.section .text
.global sovr_fastpath_call
.type sovr_fastpath_call, %function

sovr_fastpath_call:
    svc     #0
    ret
.size sovr_fastpath_call, .-sovr_fastpath_call
