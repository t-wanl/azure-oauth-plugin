// logic behind <f:validateButton />
function validateButton2(checkUrl,paramList,button) {
  button = button._button;

  var parameters = {};

  paramList.split(',').each(function(name) {
      var p = findPreviousFormItem(button,name);
      if(p!=null) {
        if(p.type=="checkbox")  parameters[name] = p.checked;
        else                    parameters[name] = p.value;
      }
  });

  var spinner = $(button).up("DIV").next();
  var target = spinner.next();
  spinner.style.display="block";

  new Ajax.Request(checkUrl, {
      parameters: parameters,
      onComplete: function(rsp) {
          spinner.style.display="none";
          applyErrorMessage(target, rsp);
          layoutUpdateCallback.call();
          var s = rsp.getResponseHeader("script");
          console.log("s = ", s);
          try {
              geval(s);
          } catch(e) {
              window.alert("failed to evaluate "+s+"\n"+e.message);
          }
      }
  });
}