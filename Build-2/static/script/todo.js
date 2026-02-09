 const todo = JSON.parse(localStorage.getItem('todoList')) || [];
displayTodoList();

function saveTodos(){
  localStorage.setItem('todoList', JSON.stringify(todo));
}

function addTodo(){
  const inputName = document.querySelector('.js-name-input');
  const dueDateElement = document.querySelector('.js-dueDate');
  todo.push({
    name: inputName.value,
    dueDate: dueDateElement.value
  });
  inputName.value = '';
  dueDateElement.value = '';
  saveTodos();
  displayTodoList();
}

function displayTodoList(){
  let todoHtml = '';
  for(let i=0; i<todo.length; i++){
    const todoObject = todo[i];
    const {name, dueDate} = todoObject;
    const html = `
      <div>${name}</div>
      <div>${dueDate} </div>
      <button onclick="
        todo.splice(${i}, 1);
        saveTodos();
        displayTodoList();
      " class="delete-button">Delete</button>
    `;
    todoHtml += html;
  }

  document.querySelector('.js-todo-list').innerHTML = todoHtml;
}