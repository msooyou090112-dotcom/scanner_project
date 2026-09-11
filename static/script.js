    let lastScroll = 0;
    const bar = document.querySelector('.highbar');

    window.addEventListener('scroll', () => {              //스크롤에 따른 메뉴바 등장
        const nowScroll = window.scrollY;

        if (nowScroll > lastScroll && nowScroll > 50) {
            bar.classList.add('hide');       
        } else {
            bar.classList.remove('hide');    
        }

        lastScroll = nowScroll;
    });

    window.addEventListener('mousemove', (e) => {
    if (e.clientY < 80) {           
        bar.classList.remove('hide');
    }
});

    window.addEventListener('mousemove', (e) => {
    if (e.clientY > 80) {           
        bar.classList.add('hide');
    }
});

window.addEventListener('scroll', () => {         //스크롤을 기능 설명 파트로 내릴 때 배경을 부드럽게 바꿔주는 코드
    const scroll = window.scrollY;
    const body = document.body;

    if (scroll === 0) {                            //배경색
        body.style.background = 'white';

    }  else if (scroll < 1080) {
        body.style.background = 'black';
    } else if (scroll < 2160) {
        body.style.background = '#152886';
    } else {
        body.style.background = '#00d4ff';
    } 
});


function typeText(el, text, speed = 40) {
    if (el.typingTimer) return;   // 이미 실행 중이면 무시
    el.textContent = '';
    let i = 0;
    el.typingTimer = setInterval(() => {
        el.textContent += text.charAt(i);
        i++;
        if (i >= text.length) {
            clearInterval(el.typingTimer);
            el.typingTimer = null;   // 끝나면 초기화
        }
    }, speed);
}

function toggle(el) {
    el.classList.toggle('open');
    if (el.classList.contains('open')) {
        const targets = el.querySelectorAll('.content p');
        targets.forEach((p, index) => {
            const t = setTimeout(() => {
                typeText(p, p.dataset.text);
            }, index * 500);
            el.dataset.timers = (el.dataset.timers || '') + t + ',';
        });

        // 다음 정거장 나타나게 하기
        if (el.classList.contains('sawall')) {
            document.querySelector('.ohwall').classList.add('visible');
        }
        if (el.classList.contains('ohwall')) {
            document.querySelector('.palwall').classList.add('visible');
        }
        if (el.classList.contains('palwall')) {
            document.querySelector('.guwall').classList.add('visible');
        }
    } else {
        // 닫을 때 예약된 setTimeout도 취소
        if (el.dataset.timers) {
            el.dataset.timers.split(',').forEach(id => clearTimeout(id));
            el.dataset.timers = '';
        }
        el.querySelectorAll('.content p').forEach(p => {
            if (p.typingTimer) clearInterval(p.typingTimer);
            p.typingTimer = null;
            p.textContent = '';
        });
    }
}

function checkAllOn() {                                //활동내용 불 다 켜지면 큰 전구 켜버리는 용도임
    const stations = document.querySelectorAll('.station');
    const allOpen = [...stations].every(s => s.classList.contains('open'));
    document.querySelector('.big-light').classList.toggle('on', allOpen);
}

// 첫 번째 정거장(4월)만 처음부터 보이게
document.querySelector('.station').classList.add('visible');

// 회원가입 때 비밀번호 보이게 해주는 버튼
document.querySelectorAll('.eye-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const input = btn.parentElement.querySelector('input');
        const eyeOpen = btn.querySelector('.eye-open');
        const eyeClosed = btn.querySelector('.eye-closed');

        if (input.type === 'password') {
            input.type = 'text';
            eyeOpen.style.display = 'none';
            eyeClosed.style.display = 'block';
        } else {
            input.type = 'password';
            eyeOpen.style.display = 'block';
            eyeClosed.style.display = 'none';
        }
    });
});

// 로그인 안하면 스캐너 못씀 ㅅㄱ
function openLoginModal() {
    document.getElementById('loginModal').classList.add('active');
}

function closeLoginModal(event) {
    // 오버레이(배경) 클릭 시 or 닫기 버튼 클릭 시
    if (!event || event.target.id === 'loginModal') {
        document.getElementById('loginModal').classList.remove('active');
    }
    if (event && event.currentTarget !== event.target && event.target.classList.contains('cancel')) {
        document.getElementById('loginModal').classList.remove('active');
    }
}

// ESC 키로도 닫기
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        document.getElementById('loginModal').classList.remove('active');
    }
});

document.getElementById('signupForm').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        // 마지막 단계면 그냥 submit (가입하기)
        if (current === steps.length - 1) return;
        
        // 아니면 다음 단계로
        e.preventDefault();
        const nextBtn = steps[current].querySelector('.next-btn');
        if (nextBtn) nextBtn.click();
    }
});
