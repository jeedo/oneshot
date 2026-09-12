import { initCreatePage } from './createPage';
import { initRevealPage } from './revealPage';

if (document.querySelector('[data-page="create"]')) {
  initCreatePage(document);
}

if (document.querySelector('[data-page="reveal"]')) {
  initRevealPage(document);
}
