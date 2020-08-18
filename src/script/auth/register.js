
$('#regInputId').keydown(function(e) {
  if(e.keyCode == 13) {
    registerCheck();
  }
});
$('#regInputPassword').keydown(function(e) {
  if(e.keyCode == 13) {
    registerCheck();
  }
});
$('#regInputEmail').keydown(function(e) {
  if(e.keyCode == 13) {
    registerCheck();
  }
});

$('#registerButton').on('click', function(e){
  registerCheck();
});


function registerCheck(){
  
  let id = $('#regInputId').val();
  let pw = $('#regInputPassword').val();
  let email = $('#regInputEmail').val();
  let name =$('#regInputName').val();
  //로그인 폼 빈칸 검사
  if(id.replace(/\s/g,"").length == 0){
    alert('아이디를 입력해주세요.');
    $('#regInputId').val('');
    $('#regInputId').focus();
    return false;
  }
  if(pw.replace(/\s/g,"").length == 0){
    alert('패스워드를 입력해주세요.');
    $('#regInputPassword').val('');
    $('#regInputPassword').focus();
    return false;
  }
  if(email.replace(/\s/g,"").length == 0){
    alert('이메일을 입력해주세요.');
    $('#regInputEmail').val('');
    $('#regInputEmail').focus();
    return false;
  }
  
  //로그인 폼 공백 검사
  let id_check = checkSpace(id)
  let pw_check = checkSpace(pw)
  let email_check = checkSpace(email)
  if(id_check == true || pw_check == true || email_check == true) {
    alert('공백은 사용하실 수 없습니다.')
    $('#regInputId').val('');
    $('#regInputPassword').val('');
    $('#regInputEmail').val('');
    $('#regInputId').focus();
    return false;
  }else {
    //로그인 아이디 특수문자 검사
    id_check = validateId(id)
    email_check = validateEmail(email);
    if(id_check == false) {
      alert('특수문자는 사용하실 수 없습니다.')
      $('#regInputId').val('');
      $('#regInputPassword').val('');
      $('#regInputId').focus();
      return false;
    }
    if(email_check == false) {
      alert('이메일 아이디 @ 도메인주소 형식을 지켜주세요.')
      $('#regInputEmail').val('');
      $('#regInputEmail').focus('');
      return false;
    }
    
    if(id_check && email_check ){
      $.ajax({
        url: '/register',
        dataType: 'json',
        type: 'POST',
        data: {'username':id,'password':pw,'email':email, 'name':name},
        success: function(result) {    
          if (result.message) {
            alert(result.message);
            return;
          }
          if (result.redirect) {
            alert('회원가입 완료!!')
            window.location.replace(result.redirect);
          }
        }
      }); 
    } 
  }
}

//공백검사 함수
function checkSpace(str) {
  if(str.search(/\s/) != -1) 
  { 
    return true; 
  } 
  else { 
    return false; 
  } 
}
//특수문자검사 함수
function validateId(id) { 
  let id_pattern = /[`~!@#$%^&*|\\\'\";:\/?]/gi; 
  if(id_pattern.test(id) == false) { 
    return true; 
  }else { 
    return false;
  } 
}
function validateEmail(email) {
  let email_pattern = /^([\w-]+(?:\.[\w-]+)*)@((?:[\w-]+\.)*\w[\w-]{0,66})\.([a-z]{2,6}(?:\.[a-z]{2})?)$/i;
  if(email_pattern.test(email) == true) {
    return true;
  }else {
    return false;
  };
}
