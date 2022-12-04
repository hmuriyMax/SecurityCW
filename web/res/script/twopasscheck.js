let a, b, c = false;

function checkFirst(el, fl, username){
    let p2 = document.getElementById("pass2");
    username = [...username].reverse().join("")
    if (el.value.length < 4 || el.value === username && fl || el.value.length > 20) {
        el.style.borderBottomColor = "#934B4B";
        a = false
    } else {
        a = true
        el.style.borderBottomColor = "#478a47";
    }
    checkSecond(p2)
    submitSwitcher()
}

function checkSecond(el){
    const p1 = document.getElementById("pass1").value;
    if (el.value !== p1) {
        el.style.borderBottomColor = "#934B4B";
        b = false
    } else {
        el.style.borderBottomColor = "#478a47";
        b = true
    }
    submitSwitcher()
}

function checkOld(el){
    if (el.value.length < 4 || el.value.length > 20) {
        el.style.borderBottomColor = "#934B4B";
        c = false
    } else {
        el.style.borderBottomColor = "#478a47";
        c = true
    }
    submitSwitcher()
}

function submitSwitcher(){
    let submit = document.getElementById("submit")
    let shark = document.getElementById("left-block")
    let fl = shark == null
    if (a && b && c){
        submit.style.outlineWidth = "2px"
        submit.style.cursor = "pointer"
        submit.style.color = "#003a59"
        submit.disabled = false
        if (fl) shark.children[0].style.outlineWidth = "30px";

    } else {
        submit.style.outlineWidth = "0px"
        submit.style.cursor = "default"
        submit.style.color = "#809caa"
        submit.disabled = true
        if (fl) shark.children[0].style.outlineWidth = "2px"
    }
}