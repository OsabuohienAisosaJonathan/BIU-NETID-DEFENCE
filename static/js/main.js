
var is_in_progress = false;
var stopped = true;

var monitor = (method_name, id) => {
  let element = document.getElementById(id);
  element.textContent = '';
  stopped == false;
  is_in_progress = true;

  let str_output = ''

  $.ajax({
    url: $SCRIPT_ROOT + '/' + method_name,
    type:'GET', 
    success:(resp, data)=>{
      str_output = resp;
      element.value = str_output; 
    },
    complete: (resp, m)=>{  
      is_in_progress = false;
      if(stopped == false ){
        monitor(method_name, id);
         // setTimeout(monitor, 200);
       }else if(stopped == true){
          element.value = str_output;
       }
    }
  });

  return str_output;
}

var ib_btn_train_model = document.getElementById('ib_btn_train_model');
if(ib_btn_train_model != null){

  ib_btn_train_model.addEventListener('click', (event)=>{
      if(is_in_progress){
      alert('Please wait, creating model');
      return;
    }
    // monitor('readConsoleText', 'id_txt_model_output');
    $.ajax({
      url: $SCRIPT_ROOT + '/create_model',
      type:'GET', 
      success:(resp, data)=>{
        document.getElementById('id_txt_model_output').value = resp;
      },complete: (resp, m)=>{ 
        $.ajax({
          url: $SCRIPT_ROOT + '/readConsoleText',
          type:'GET', 
          success:(resp, data)=>{
            document.getElementById('id_txt_model_output').value = resp; 
          } 
        });
      }
    });
  });

  document.getElementById('ib_btn_clear_result').addEventListener('click', (event)=>{
    document.getElementById('id_txt_model_output').value = ''; 
  }); 
}


var id_btn_predict = document.getElementById('id_btn_predict');
if(id_btn_predict != null){
  id_btn_predict.addEventListener('click', (event)=>{
    if(is_in_progress){
      alert('Please wait, creating model');
      return;
    }

    let gender = document.getElementById('id_slt_gender').value;
    let lang = document.getElementById('id_slt_lang').value;
    let statuses = document.getElementById('id_txt_statuses_count').value;
    let followers = document.getElementById('id_txt_followers_count').value;
    let friends = document.getElementById('id_txt_friends_count').value;
    let favourites = document.getElementById('id_txt_favourites_count').value;
    let listing = document.getElementById('id_txt_listed_count').value; 

    if(gender == '' || lang == '' || statuses == '' || friends == '' ||
      favourites == '' || listing == '' || followers == ''){
      alert("Input values can't be null.");
      return ;
    }

    monitor('method_name', 'id_pediction_result');
    $.ajax({
      url: $SCRIPT_ROOT + '/predict_profile?gender='+gender+'&lang='+lang
        +'&statuses='+statuses+'&followers='+followers+'&friends='+friends
        +'&favourites='+favourites+'&listing='+listing,
      type:'GET', 
      success:(resp, data)=>{
          let msg = resp.pred + '\n\n' + resp.stalker;
         document.getElementById('id_pediction_result').value = msg;
      }
    })
  }); 
}


var id_div_evaluate = document.getElementById('id_div_evaluate');
if(id_div_evaluate != null){
  id_div_evaluate.addEventListener('click', (event)=>{ 
    $("#id_img_evaluate").attr('src', ''); 
    $.ajax({
        url: $SCRIPT_ROOT + '/plot_evaluation',
        type:'GET', 
        success:(resp, data)=>{  
          if(resp.msg != 'none'){
            alert(resp.msg);
          }else{
            document.getElementById('id_test_loss').innerHTML = 'test loss: '+resp.test_loss;
            document.getElementById('id_acc').innerHTML = 'test acc: '+resp.test_acc; 
            $("#id_img_evaluate").attr('src', resp.plt_img); 
          } 
        }
      });
  }); 

  document.getElementById('id_div_roc').addEventListener('click', (event)=>{ 
    $("#id_img_evaluate").attr('src', ''); 
    $.ajax({
        url: $SCRIPT_ROOT + '/plot_roc_curve',
        type:'GET', 
        success:(resp, data)=>{          
          document.getElementById('id_fpos').innerHTML = 'false positive rate: '+resp.false_positive_rate ;
          document.getElementById('id_tpos').innerHTML = 'true positive rate: '+resp.true_positive_rate;
          document.getElementById('id_roc_acc').innerHTML = 'roc auc:  '+resp.roc_auc;
          $("#id_img_evaluate").attr('src', resp.plt_img);  
        }
      });
  }); 

  document.getElementById('id_div_learning_curve').addEventListener('click', (event)=>{
    let result = '';
    $("#id_img_evaluate").attr('src', ''); 
    $.ajax({
        url: $SCRIPT_ROOT + '/plot_learning_curve',
        type:'GET', 
        success:(resp, data)=>{
          $("#id_img_evaluate").attr('src', resp.plt_img);  
        }
      });
  }); 
}